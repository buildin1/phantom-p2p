//! 安装包下载与校验。
//!
//! # 为什么在 core 里
//!
//! 下载、校验、落盘这三件事在 PC 与移动端是同一套逻辑，而且都只依赖 core
//! 已有的 `ureq` 与 `sha2`，不引入任何新依赖。**唤起安装**才是平台相关的：
//! Windows 要启动 NSIS 安装器，Android 要走 `PackageInstaller` ——
//! 那一步留给各端自己做。
//!
//! 这是一个**新增模块**，不改动 core 里任何已有函数的签名或行为。
//!
//! # sha256 不是可选项
//!
//! 没有校验的自动安装等于把用户设备交给任何能劫持下载的人。校验不通过时
//! 这里会删掉半成品并返回错误 —— 绝不把一个来路不明的包留在磁盘上等着被误用。

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// 下载过程的进度回调：`(已下载字节, 总字节)`。总字节为 0 表示服务器没给
/// `Content-Length` —— 这时候不要编一个假的百分比出来。
pub type ProgressFn<'a> = &'a mut dyn FnMut(u64, u64);

/// 单次读取的块大小。64 KiB 是磁盘吞吐与回调频率之间的常规折中：
/// 太小回调过密拖慢下载，太大进度条一跳一大格。
const CHUNK: usize = 64 * 1024;

/// 下载安装包到 `dest`，并校验 SHA-256。
///
/// 成功返回落盘路径；任何一步失败都会删掉半成品文件再返回错误。
///
/// `expected_sha256` 必须是 64 位小写或大写十六进制，比较时忽略大小写。
pub fn download_and_verify(
    url: &str,
    dest: &Path,
    expected_sha256: &str,
    progress: ProgressFn<'_>,
) -> Result<PathBuf, String> {
    if expected_sha256.len() != 64 || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        // 宁可不更新，也不装一个无法验证的包。
        return Err("校验值不是 64 位十六进制，拒绝下载".to_string());
    }

    // 先清掉可能存在的上一次残留：续传在这里没有意义（包不大，而且
    // 半个包的摘要一定对不上），但一个旧残包会让人误以为下载成功了。
    let _ = std::fs::remove_file(dest);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建下载目录失败: {}", e))?;
    }

    let response = ureq::get(url)
        .timeout(std::time::Duration::from_secs(300))
        .call()
        .map_err(|e| format!("下载失败: {}", e))?;

    let total: u64 = response
        .header("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut reader = response.into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| format!("创建文件失败: {}", e))?;
    // 一边落盘一边算摘要。读两遍文件在慢设备上是可感知的额外几秒，
    // 而这几秒正好卡在用户盯着进度条的时候。
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut written: u64 = 0;

    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(dest);
                return Err(format!("读取下载流失败: {}", e));
            }
        };
        if let Err(e) = file.write_all(&buffer[..read]) {
            let _ = std::fs::remove_file(dest);
            return Err(format!("写入文件失败: {}", e));
        }
        hasher.update(&buffer[..read]);
        written += read as u64;
        progress(written, total);
    }

    if let Err(e) = file.flush() {
        let _ = std::fs::remove_file(dest);
        return Err(format!("落盘失败: {}", e));
    }
    drop(file);

    let actual = hasher.finalize();
    let actual_hex: String = actual.iter().map(|b| format!("{:02x}", b)).collect();

    if !actual_hex.eq_ignore_ascii_case(expected_sha256) {
        // 这不是"重试一下就好"的错误：要么包被改过，要么发布信息配错了。
        // 两种情况都绝不能让它留在盘上。
        warn!(
            "[更新] SHA-256 不匹配：期望 {}，实际 {}",
            expected_sha256, actual_hex
        );
        let _ = std::fs::remove_file(dest);
        return Err("安装包校验失败，已丢弃".to_string());
    }

    info!("[更新] 安装包校验通过：{} ({} 字节)", dest.display(), written);
    Ok(dest.to_path_buf())
}

/// 比较两个版本号。`a < b` 时返回 `Ordering::Less`。
///
/// 必须按数字逐段比，不能按字符串比：字符串序下 "3.2.10" < "3.2.9"，
/// 于是刚发的 3.2.10 会被判成比 3.2.9 旧。解析不出来的段按 0 处理。
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    parse_version(a).cmp(&parse_version(b))
}

fn parse_version(raw: &str) -> (u32, u32, u32) {
    // 去掉 "-dev" / "-debug" 这类后缀，只看数字部分。
    let core = raw.trim().split(['-', '+']).next().unwrap_or("");
    let mut parts = core.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn version_compare_is_numeric_not_lexical() {
        // 这一条就是这个函数存在的理由：字符串序下 "3.2.10" < "3.2.9"。
        assert_eq!(compare_versions("3.2.10", "3.2.9"), Ordering::Greater);
        assert_eq!(compare_versions("3.2.2", "3.3.0"), Ordering::Less);
        assert_eq!(compare_versions("3.2.2", "3.2.2"), Ordering::Equal);
        // 带后缀的版本按数字部分比，不能因为多了 "-dev" 就判成更新。
        assert_eq!(compare_versions("3.3.0-dev", "3.3.0"), Ordering::Equal);
        // 段数不全时缺的按 0 补。
        assert_eq!(compare_versions("3.3", "3.3.0"), Ordering::Equal);
        assert_eq!(compare_versions("4", "3.9.9"), Ordering::Greater);
    }

    #[test]
    fn rejects_malformed_checksum_before_downloading() {
        let dest = std::env::temp_dir().join("phantom-update-test-never-created.bin");
        let mut noop = |_: u64, _: u64| {};
        // URL 是无效的，但函数必须在碰网络之前就因为校验值不合法而拒绝 ——
        // 也就是说这个测试不会产生任何网络请求。
        let result = download_and_verify("http://127.0.0.1:1/x", &dest, "abc", &mut noop);
        assert!(result.is_err());
        assert!(!dest.exists(), "拒绝的下载不该留下文件");
    }
}
