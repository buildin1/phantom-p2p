//! 客户端日志分层与轮转
//!
//! # 设计前提
//!
//! 观测模型是**集中式**的：用户不会主动收集日志，所以客户端不面向用户
//! 暴露诊断信息，而是把日志文件上报到信令服务器做聚合分析。
//! 这决定了本地日志的要求——**可被机器消费**，而不是给人看。
//!
//! # 为什么要分层
//!
//! 实测单次 8 小时会话产出 48,736 行 / 6 MB，其中 **91.4% 是 DEBUG**，
//! 且绝大多数是每秒一条、数值完全相同的心跳（带宽采样、`get_stats`、
//! QUIC path 统计）。真正有价值的打洞过程被淹没在里面。
//!
//! 拆分规则按**用途**而非级别：
//!
//! | 文件 | 内容 | 级别 |
//! |---|---|---|
//! | `ice.log` | 打洞全过程（核心，值得全量记） | DEBUG |
//! | `signal.log` | 信令连接、鉴权、房间、消息收发 | INFO |
//! | `tunnel.log` | 隧道、TUN、数据面 | INFO |
//! | `app.log` | 其余一切 | INFO |
//!
//! 高频心跳指标不进文本日志——它们属于结构化指标，
//! 走 [`phantom_protocol::PunchRecord`] 那条路。
//!
//! # 重复抑制
//!
//! 同一模板在短时间内重复出现时只保留首末两条，中间折叠为计数。
//! 这是把 6 MB 压到可上报体积的关键。

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 单个日志文件的大小上限；超过即轮转
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// 每个日志保留的历史份数
const MAX_BACKUPS: usize = 5;
/// 重复抑制窗口
const DEDUP_WINDOW: Duration = Duration::from_secs(10);

/// 按大小轮转的文件写入器。
///
/// `tracing_appender` 只提供按时间轮转，但我们要控的是**上报体积**——
/// 按时间轮转在空闲时产生一堆空文件，在繁忙时又可能单文件涨到几百 MB。
struct RollingFile {
    dir: PathBuf,
    stem: String,
    file: Option<File>,
    written: u64,
}

impl RollingFile {
    fn new(dir: &Path, stem: &str) -> Self {
        let mut rf = Self {
            dir: dir.to_path_buf(),
            stem: stem.to_string(),
            file: None,
            written: 0,
        };
        rf.open();
        rf
    }

    fn path(&self) -> PathBuf {
        self.dir.join(format!("{}.log", self.stem))
    }

    fn open(&mut self) {
        let path = self.path();
        self.written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
    }

    /// 轮转：`x.log` → `archive/x.1.log`，旧的依次后移，超出份数的丢弃
    fn rotate(&mut self) {
        self.file = None;
        let archive = self.dir.join("archive");
        let _ = std::fs::create_dir_all(&archive);

        let oldest = archive.join(format!("{}.{}.log", self.stem, MAX_BACKUPS));
        let _ = std::fs::remove_file(&oldest);
        for i in (1..MAX_BACKUPS).rev() {
            let from = archive.join(format!("{}.{}.log", self.stem, i));
            let to = archive.join(format!("{}.{}.log", self.stem, i + 1));
            let _ = std::fs::rename(&from, &to);
        }
        let _ = std::fs::rename(self.path(), archive.join(format!("{}.1.log", self.stem)));
        self.open();
    }
}

impl Write for RollingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written >= MAX_FILE_BYTES {
            self.rotate();
        }
        match self.file.as_mut() {
            Some(f) => {
                let n = f.write(buf)?;
                self.written += n as u64;
                Ok(n)
            }
            // 打不开文件时静默丢弃：日志写不进去绝不能拖垮业务
            None => Ok(buf.len()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// 把日志按 target 路由到不同文件，并做重复抑制。
#[derive(Clone)]
pub struct LogRouter {
    inner: Arc<Mutex<RouterInner>>,
}

struct RouterInner {
    ice: RollingFile,
    signal: RollingFile,
    tunnel: RollingFile,
    app: RollingFile,
    /// 模板 → (首次出现时刻, 已折叠条数)
    dedup: HashMap<String, (Instant, u32)>,
}

impl LogRouter {
    pub fn new(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(RouterInner {
                ice: RollingFile::new(dir, "ice"),
                signal: RollingFile::new(dir, "signal"),
                tunnel: RollingFile::new(dir, "tunnel"),
                app: RollingFile::new(dir, "app"),
                dedup: HashMap::new(),
            })),
        })
    }
}

/// 把一条日志行归一化成"模板"用于重复抑制：
/// 抹掉时间戳与所有数字，只保留骨架。
///
/// 例：`[QUIC] path=1.2.3.4:10204 rtt=308ms sent=86332` 与
/// 下一秒数值不同的同类行会归一到同一个模板。
fn template_of(line: &str) -> String {
    let body = line.split_once(" INFO ").map(|(_, b)| b).unwrap_or(line);
    let mut out = String::with_capacity(body.len());
    let mut in_num = false;
    for c in body.chars() {
        if c.is_ascii_digit() {
            if !in_num {
                out.push('#');
                in_num = true;
            }
        } else {
            in_num = false;
            out.push(c);
        }
    }
    out
}

/// 按 target 选择目标文件。
///
/// **按模块路径的末段精确匹配**，不能用 `contains`——
/// `"stun"` 里含 `"tun"`，用子串匹配会把 STUN 日志错误地分到 `tunnel.log`，
/// 实测导致排查打洞失败时在 `ice.log` 里完全看不到 STUN 的超时原因。
fn route_of(target: &str) -> Target {
    let module = target.rsplit("::").next().unwrap_or(target);
    match module {
        // 打洞链路：STUN 是其中不可分割的一环，失败原因必须和打洞过程放在一起
        "punch" | "ice" | "stun" | "nat" | "puncher" => Target::Ice,
        "client" | "signal" => Target::Signal,
        "tunnel" | "tun" | "tun_bridge" | "udp_tunnel" | "crypto" => Target::Tunnel,
        _ => {
            // 兜底：模块名未收录时按路径里的关键词粗分，
            // 但仍要保证 stun 不被 tun 抢走
            if target.contains("stun") || target.contains("punch") || target.contains("ice") {
                Target::Ice
            } else if target.contains("signal") {
                Target::Signal
            } else if target.contains("tun") {
                Target::Tunnel
            } else {
                Target::App
            }
        }
    }
}

enum Target {
    Ice,
    Signal,
    Tunnel,
    App,
}

impl LogRouter {
    /// 写入一行（已格式化）。返回是否真的落盘（被抑制则为 false）。
    ///
    /// `dedupable` 为 false 时跳过重复抑制。**WARN/ERROR 绝不折叠**——
    /// 去重是为了压掉每秒一条的心跳 DEBUG，而告警本来就稀疏，
    /// 每一条的具体参数都是排障线索。实测曾把 STUN 对备用端口 3479 的
    /// 查询失败和主端口 3478 的折叠成一条（模板去掉数字后相同），
    /// 导致日志里看不出备用端口也试过。
    pub fn write_line(&self, target: &str, line: &str, dedupable: bool) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        if !dedupable {
            let _ = write_to(&mut inner, target, line);
            return true;
        }

        // 重复抑制：窗口内同模板只留首条，其余累计计数
        let key = template_of(line);
        let now = Instant::now();
        let suppressed = match inner.dedup.get_mut(&key) {
            Some((first, count)) if now.duration_since(*first) < DEDUP_WINDOW => {
                *count += 1;
                true
            }
            Some((first, count)) => {
                // 窗口结束：把折叠掉的数量补记一行，避免"丢了多少"无从得知
                let folded = *count;
                *first = now;
                *count = 0;
                if folded > 0 {
                    let note = format!("    ... 上一条模板在窗口内重复 {} 次\n", folded);
                    let _ = write_to(&mut inner, target, &note);
                }
                false
            }
            None => {
                inner.dedup.insert(key, (now, 0));
                false
            }
        };
        if suppressed {
            return false;
        }
        let _ = write_to(&mut inner, target, line);
        true
    }
}

fn write_to(inner: &mut RouterInner, target: &str, s: &str) -> io::Result<()> {
    let f: &mut RollingFile = match route_of(target) {
        Target::Ice => &mut inner.ice,
        Target::Signal => &mut inner.signal,
        Target::Tunnel => &mut inner.tunnel,
        Target::App => &mut inner.app,
    };
    f.write_all(s.as_bytes())?;
    f.flush()
}

/// 安装分层日志。
///
/// 控制台仍打全量（开发时方便），文件侧按 target 分流并做重复抑制。
/// `ice` target 单独提到 DEBUG——打洞是核心，值得全量记；
/// 其余保持 INFO，避免每秒一条的心跳把文件撑爆。
pub fn init(log_dir: &Path, dev_mode: bool) -> Result<LogRouter, String> {
    use tracing_subscriber::prelude::*;

    let router = LogRouter::new(log_dir).map_err(|e| format!("创建日志目录失败: {e}"))?;

    // ice/punch 单独开 DEBUG；其余 INFO。心跳类指标不进文本日志。
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "info,phantom_core::punch=debug,phantom_core::ice=debug,phantom_core::stun=debug".into()
    });

    let console = tracing_subscriber::fmt::layer().with_ansi(dev_mode);
    let files = RouterLayer {
        router: router.clone(),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(files)
        .init();

    Ok(router)
}

/// 把 tracing 事件格式化成一行并交给 [`LogRouter`] 分流
struct RouterLayer {
    router: LogRouter,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RouterLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let line = format!(
            "{} {:>5} {}: {}\n",
            chrono_like_now(),
            meta.level(),
            meta.target(),
            visitor.0
        );
        // 只对 DEBUG/TRACE 去重：告警稀疏且每条参数都是线索，折叠会丢诊断信息
        let dedupable = matches!(*meta.level(), tracing::Level::DEBUG | tracing::Level::TRACE);
        self.router.write_line(meta.target(), &line, dedupable);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_str(&format!("{:?}", value));
        } else {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
}

/// 轻量时间戳（避免为一行日志引入 chrono 依赖）
fn chrono_like_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let ms = now.subsec_millis();
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms)
}

/// 收集 `log/` 下的全部日志文件路径，供"用户主动反馈"时打包上报。
pub fn collect_log_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in [dir.to_path_buf(), dir.join("archive")] {
        if let Ok(entries) = std::fs::read_dir(&sub) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "log").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_collapses_varying_numbers() {
        let a = "[QUIC] path=1.2.3.4:10204 rtt=308ms sent=86332 lost=180";
        let b = "[QUIC] path=1.2.3.4:10204 rtt=294ms sent=86333 lost=181";
        assert_eq!(template_of(a), template_of(b), "只有数值不同应归为同一模板");
    }

    #[test]
    fn template_keeps_structurally_different_lines_apart() {
        let a = "[TUN] no peer route for 1.2.3.4 -> 5.6.7.8";
        let b = "[TUN] peer forward queue rejected packet 1.2.3.4 -> 5.6.7.8";
        assert_ne!(template_of(a), template_of(b));
    }

    /// 打洞是核心，必须单独成文件——它被淹在 91% 的心跳噪声里正是原来的问题
    #[test]
    fn punch_and_ice_targets_route_to_ice_log() {
        assert!(matches!(route_of("phantom_core::punch"), Target::Ice));
        assert!(matches!(route_of("phantom_core::ice"), Target::Ice));
    }

    /// 回归测试：`"stun"` 里含 `"tun"`。早先用 `contains` 匹配把 STUN 日志
    /// 错误分流到了 tunnel.log，排查打洞失败时在 ice.log 里根本看不到
    /// STUN 超时这个根因。STUN 是打洞链路不可分割的一环，必须同文件。
    #[test]
    fn stun_logs_go_to_ice_not_tunnel() {
        assert!(
            matches!(route_of("phantom_core::stun"), Target::Ice),
            "STUN 属于打洞链路，不能因为 'stun' 含 'tun' 就被分到 tunnel"
        );
        assert!(matches!(route_of("phantom_core::nat"), Target::Ice));
        // 真正的 tunnel 模块仍要落到 tunnel.log
        assert!(matches!(route_of("phantom_core::tunnel"), Target::Tunnel));
        assert!(matches!(
            route_of("phantom_core::tun_bridge"),
            Target::Tunnel
        ));
    }

    #[test]
    fn targets_route_to_expected_files() {
        assert!(matches!(
            route_of("phantom_core::signal::client"),
            Target::Signal
        ));
        assert!(matches!(
            route_of("phantom_core::udp_tunnel"),
            Target::Tunnel
        ));
        assert!(matches!(route_of("phantom_p2p_lib"), Target::App));
    }

    #[test]
    fn repeated_lines_are_suppressed_within_window() {
        let dir = std::env::temp_dir().join(format!("phantom-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let router = LogRouter::new(&dir).unwrap();

        let t = "phantom_core::tunnel";
        assert!(
            router.write_line(t, "[QUIC] rtt=1ms sent=1\n", true),
            "首条应落盘"
        );
        // 同模板（仅数值不同）在窗口内应被抑制
        assert!(!router.write_line(t, "[QUIC] rtt=2ms sent=2\n", true));
        assert!(!router.write_line(t, "[QUIC] rtt=3ms sent=3\n", true));
        // 结构不同的行不受影响
        assert!(router.write_line(t, "[TUN] device closed\n", true));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归测试：告警不参与去重。
    ///
    /// 早先 STUN 对 3478 与 3479 两个端口的失败被折叠成一条
    /// （模板抹掉数字后完全相同），日志里看不出备用端口也试过。
    #[test]
    fn warnings_are_never_folded_even_when_templates_match() {
        let dir = std::env::temp_dir().join(format!("phantom-warn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let router = LogRouter::new(&dir).unwrap();

        let t = "phantom_core::stun";
        assert!(router.write_line(t, "[STUN] 查询失败: host:3478\n", false));
        assert!(
            router.write_line(t, "[STUN] 查询失败: host:3479\n", false),
            "仅端口不同的告警必须各自留存，否则丢掉排障线索"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_preserves_recent_history() {
        let dir = std::env::temp_dir().join(format!("phantom-rot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut rf = RollingFile::new(&dir, "t");
        rf.written = MAX_FILE_BYTES; // 强制触发轮转
        rf.write_all(b"after-rotate\n").unwrap();
        rf.flush().unwrap();

        assert!(
            dir.join("archive").join("t.1.log").exists(),
            "轮转后旧文件应进入 archive"
        );
        assert!(dir.join("t.log").exists(), "轮转后应重新打开当前文件");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_log_files_includes_archive() {
        let dir = std::env::temp_dir().join(format!("phantom-collect-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("archive")).unwrap();
        std::fs::write(dir.join("ice.log"), b"x").unwrap();
        std::fs::write(dir.join("archive").join("ice.1.log"), b"y").unwrap();
        std::fs::write(dir.join("notes.txt"), b"z").unwrap();

        let files = collect_log_files(&dir);
        assert_eq!(files.len(), 2, "应收集当前与归档的 .log，忽略其它文件");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
