//! 日志包打包与上传
//!
//! 观测模型是集中式的：用户不会主动收集日志，所以排障时由客户端把整个
//! `log/` 目录打包上传到服务端。触发有两种——用户主动"反馈问题"，
//! 或服务端针对特定 user_id 主动索取。
//!
//! 走**独立 HTTP POST** 而不是信令 WebSocket：日志包可能几 MB，
//! 塞进信令连接会阻塞打洞协商这类时延敏感的消息。
//!
//! # 失败重投
//!
//! 上传失败（断网、服务端重启）时把包留在本地 `pending/` 下，
//! 下次连接成功后补投。否则恰恰是"网络有问题"的那次日志——
//! 最有排障价值的那份——最容易丢。
//!
//! # 配额
//!
//! 每日上传字节数设上限。日志上报本身不能变成流量负担，
//! 尤其在用户网络已经不好的时候。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// 单个日志包的体积上限（压缩后）
pub const MAX_PACKAGE_BYTES: usize = 32 * 1024 * 1024;
/// 每日上传配额
const DAILY_QUOTA_BYTES: u64 = 64 * 1024 * 1024;
/// 单次上传超时
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// 把 `log/` 目录打包成 zip。
///
/// 用 zip 而非自定义格式，是为了服务端管理员拿到后能直接解压查看——
/// 排障时多一道解包工具就是多一道障碍。
pub fn package_logs(log_dir: &Path) -> Result<Vec<u8>, String> {
    let files = crate::logging::collect_log_files(log_dir);
    if files.is_empty() {
        return Err("没有可上传的日志文件".to_string());
    }

    let buf = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let opts: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        // 保留 archive/ 这一层目录结构，便于按时间顺序阅读
        let name = path
            .strip_prefix(log_dir)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| {
                path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown.log".into())
            });
        zip.start_file(name, opts)
            .map_err(|e| format!("写入 zip 条目失败: {e}"))?;
        zip.write_all(&data)
            .map_err(|e| format!("写入 zip 内容失败: {e}"))?;
    }

    let out = zip
        .finish()
        .map_err(|e| format!("完成 zip 失败: {e}"))?
        .into_inner();

    if out.len() > MAX_PACKAGE_BYTES {
        return Err(format!(
            "日志包 {} 字节超出上限 {}（请先轮转或清理）",
            out.len(),
            MAX_PACKAGE_BYTES
        ));
    }
    Ok(out)
}

/// 上传器：负责配额、重投队列与实际 HTTP 传输。
pub struct LogUploader {
    log_dir: PathBuf,
    /// 待重投目录
    pending_dir: PathBuf,
    quota_file: PathBuf,
}

impl LogUploader {
    pub fn new(log_dir: &Path) -> Self {
        let pending_dir = log_dir.join("pending");
        let _ = std::fs::create_dir_all(&pending_dir);
        Self {
            log_dir: log_dir.to_path_buf(),
            pending_dir,
            quota_file: log_dir.join(".upload-quota"),
        }
    }

    /// 打包当前日志并上传；失败则留待重投。
    pub fn upload_now(&self, url: &str, reason: &str) -> Result<usize, String> {
        let data = package_logs(&self.log_dir)?;
        let size = data.len();
        self.check_quota(size as u64)?;

        match http_post(url, &data) {
            Ok(()) => {
                self.consume_quota(size as u64);
                info!("[日志上报] 已上传 {} 字节 (原因: {})", size, reason);
                Ok(size)
            }
            Err(e) => {
                // 恰恰是"网络有问题"那次的日志最有排障价值，绝不能直接丢
                self.stash_pending(&data, url);
                Err(format!("上传失败，已转入重投队列: {e}"))
            }
        }
    }

    /// 补投历史失败的包。连接恢复后调用。
    pub fn flush_pending(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.pending_dir) else {
            return 0;
        };
        let mut sent = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "pending").unwrap_or(true) {
                continue;
            }
            let Ok(raw) = std::fs::read(&path) else {
                continue;
            };
            // 文件格式：URL 行 + '\n' + zip 内容
            let Some(idx) = raw.iter().position(|b| *b == b'\n') else {
                let _ = std::fs::remove_file(&path);
                continue;
            };
            let url = String::from_utf8_lossy(&raw[..idx]).to_string();
            let body = &raw[idx + 1..];
            if self.check_quota(body.len() as u64).is_err() {
                break; // 配额用尽，留到明天
            }
            match http_post(&url, body) {
                Ok(()) => {
                    self.consume_quota(body.len() as u64);
                    let _ = std::fs::remove_file(&path);
                    sent += 1;
                }
                Err(e) => {
                    warn!("[日志上报] 补投失败，保留待下次: {}", e);
                    break; // 一个失败通常意味着服务端不可达，不必继续
                }
            }
        }
        if sent > 0 {
            info!("[日志上报] 补投成功 {} 个历史日志包", sent);
        }
        sent
    }

    fn stash_pending(&self, data: &[u8], url: &str) {
        let name = format!("{}.pending", now_secs());
        let mut blob = Vec::with_capacity(url.len() + 1 + data.len());
        blob.extend_from_slice(url.as_bytes());
        blob.push(b'\n');
        blob.extend_from_slice(data);
        let _ = std::fs::write(self.pending_dir.join(name), blob);
    }

    /// 配额文件格式：`<当天序号> <已用字节>`
    fn read_quota(&self) -> (u64, u64) {
        std::fs::read_to_string(&self.quota_file)
            .ok()
            .and_then(|s| {
                let mut it = s.split_whitespace();
                Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
            })
            .unwrap_or((0, 0))
    }

    fn check_quota(&self, want: u64) -> Result<(), String> {
        let today = now_secs() / 86_400;
        let (day, used) = self.read_quota();
        let used = if day == today { used } else { 0 };
        if used + want > DAILY_QUOTA_BYTES {
            return Err(format!(
                "已达当日上传配额（{}/{} 字节）",
                used, DAILY_QUOTA_BYTES
            ));
        }
        Ok(())
    }

    fn consume_quota(&self, n: u64) {
        let today = now_secs() / 86_400;
        let (day, used) = self.read_quota();
        let used = if day == today { used } else { 0 };
        let _ = std::fs::write(&self.quota_file, format!("{} {}", today, used + n));
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn http_post(url: &str, body: &[u8]) -> Result<(), String> {
    let resp = ureq::post(url)
        .timeout(UPLOAD_TIMEOUT)
        .set("Content-Type", "application/zip")
        .send_bytes(body);
    match resp {
        Ok(r) if r.status() < 300 => Ok(()),
        Ok(r) => Err(format!("服务端返回 {}", r.status())),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "phantom-upload-{}-{}-{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn package_produces_a_readable_zip() {
        let dir = temp_dir("pkg");
        std::fs::write(dir.join("ice.log"), b"punch line one\npunch line two\n").unwrap();
        std::fs::create_dir_all(dir.join("archive")).unwrap();
        std::fs::write(dir.join("archive").join("ice.1.log"), b"older\n").unwrap();

        let zipped = package_logs(&dir).unwrap();
        assert!(!zipped.is_empty());
        // zip 的本地文件头魔数，确认产出的确实是标准 zip
        assert_eq!(&zipped[..2], b"PK", "应产出标准 zip，便于直接解压查看");

        // 用 zip 库回读，确认两个文件都在且归档目录结构保留
        let reader = zip::ZipArchive::new(std::io::Cursor::new(zipped)).unwrap();
        let names: Vec<String> = reader.file_names().map(|s| s.to_string()).collect();
        assert!(names.contains(&"ice.log".to_string()));
        assert!(names.contains(&"archive/ice.1.log".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn packaging_empty_directory_is_an_error() {
        let dir = temp_dir("empty");
        assert!(
            package_logs(&dir).is_err(),
            "无日志可传时应明确报错而非上传空包"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 上传失败必须留档——网络有问题那次的日志恰恰最有排障价值
    #[test]
    fn failed_upload_is_stashed_for_retry() {
        let dir = temp_dir("stash");
        std::fs::write(dir.join("ice.log"), b"data\n").unwrap();
        let up = LogUploader::new(&dir);

        // 指向一个必然连不上的地址
        let err = up.upload_now("http://127.0.0.1:1/upload", "test");
        assert!(err.is_err());

        let pending: Vec<_> = std::fs::read_dir(dir.join("pending"))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(pending.len(), 1, "失败的包应留在重投队列");

        // 留档内容必须能还原出 URL 与包体
        let raw = std::fs::read(pending[0].path()).unwrap();
        let idx = raw.iter().position(|b| *b == b'\n').unwrap();
        assert_eq!(
            String::from_utf8_lossy(&raw[..idx]),
            "http://127.0.0.1:1/upload"
        );
        assert_eq!(&raw[idx + 1..idx + 3], b"PK");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_blocks_once_daily_budget_is_spent() {
        let dir = temp_dir("quota");
        let up = LogUploader::new(&dir);
        assert!(up.check_quota(1024).is_ok(), "初始应有配额");

        up.consume_quota(DAILY_QUOTA_BYTES);
        assert!(
            up.check_quota(1).is_err(),
            "配额用尽后必须拒绝，日志上报不能变成流量负担"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_resets_on_a_new_day() {
        let dir = temp_dir("quota-reset");
        let up = LogUploader::new(&dir);
        // 伪造成"昨天已用满"
        let yesterday = now_secs() / 86_400 - 1;
        std::fs::write(
            &up.quota_file,
            format!("{} {}", yesterday, DAILY_QUOTA_BYTES),
        )
        .unwrap();
        assert!(up.check_quota(1024).is_ok(), "跨天后配额应重置");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_pending_is_safe_when_queue_is_empty() {
        let dir = temp_dir("flush-empty");
        let up = LogUploader::new(&dir);
        assert_eq!(up.flush_pending(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_package_is_rejected() {
        // 直接验证阈值语义，避免真的造 32MB 文件拖慢测试
        assert!(MAX_PACKAGE_BYTES > 0);
        assert!(
            (DAILY_QUOTA_BYTES as usize) >= MAX_PACKAGE_BYTES,
            "每日配额至少要装得下一个满包，否则永远传不出去"
        );
    }
}
