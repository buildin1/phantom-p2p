//! 服务端文件日志。
//!
//! # 为什么不复用 `phantom_core::logging`
//!
//! 服务端只依赖 `phantom-protocol`，**不依赖 `phantom-core`**——后者装的是
//! TUN 虚拟网卡、QUIC 隧道、NAT 打洞、overlay 加密这些纯客户端的东西，
//! 服务端没有理由把它们全背上。所以那套 `LogRouter` 对服务端本来就不可见，
//! 不是"忘了调"。
//!
//! 而且客户端那套的核心是**按 target 分流**成 app/ice/signal/tunnel 四个文件，
//! 服务端没有对应的模块划分，照搬过来只会得到一个文件加三个空文件，没有意义。
//! 这里只做服务端真正需要的部分：落盘 + 按天轮转 + 控制台照旧。
//!
//! # 为什么必须落盘
//!
//! 在这之前服务端只有 `tracing_subscriber::fmt()`，也就是只写 stdout。
//! 实际排查打洞问题时发现：客户端两端的日志都能翻，唯独中间**真正决定
//! 配对结果**的服务端是个黑盒——而 Windows 控制台的回滚缓冲区有上限，
//! 跑一会儿关键的那几行就被刷没了，事后完全无从对证。

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;

/// 保留多少个轮转出来的日志文件（按天轮转，即约两周）。
///
/// 服务端是长期运行的进程，不设上限迟早把磁盘写满；两周足够覆盖
/// "用户报障 → 捞日志" 这个来回。
const MAX_LOG_FILES: usize = 14;

/// 日志系统的存活句柄。
///
/// **必须在 `main` 里一直持有到进程退出**：非阻塞写入器的后台线程靠这个
/// guard 存活，提前 drop 会导致还在队列里的日志被丢掉。
pub struct Handles {
    _console: WorkerGuard,
    _file: Option<WorkerGuard>,
    /// 文件日志没能装上的原因。日志系统此时还没就绪，没法直接打出来，
    /// 交给调用方在装好之后再报。
    pub file_error: Option<String>,
}

/// 安装日志系统：控制台照旧，同时按天轮转写入 `log_dir`。
///
/// **不会失败**——文件日志装不上（目录只读、磁盘满等）时退化成只有控制台，
/// 原因放在 [`Handles::file_error`] 里带回去。服务端不该因为写不了日志就起不来。
pub fn init(log_dir: &Path, default_filter: &str) -> Handles {
    // 控制台也走非阻塞包装：Windows 控制台在高频输出下本身就慢，
    // 不包一层会让写日志这件事直接拖慢信令处理。
    let (console_writer, console_guard) = tracing_appender::non_blocking(std::io::stdout());

    let (file_layer, file_guard, file_error) = match build_file_appender(log_dir) {
        Ok(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let layer = tracing_subscriber::fmt::layer()
                // 文件里不要 ANSI 转义，否则用编辑器打开满屏乱码
                .with_ansi(false)
                .with_writer(writer);
            (Some(layer), Some(guard), None)
        }
        Err(e) => (None, None, Some(e)),
    };

    // 过滤器挂在 registry 上，控制台和文件共用同一套规则——
    // 两边看到的内容一致，事后拿文件对证时不会有"控制台有、文件没有"的坑。
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| default_filter.into());

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(console_writer))
        .with(file_layer)
        .init();

    Handles {
        _console: console_guard,
        _file: file_guard,
        file_error,
    }
}

fn build_file_appender(
    log_dir: &Path,
) -> Result<tracing_appender::rolling::RollingFileAppender, String> {
    std::fs::create_dir_all(log_dir).map_err(|e| format!("创建日志目录失败: {e}"))?;
    tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("server")
        .filename_suffix("log")
        .max_log_files(MAX_LOG_FILES)
        .build(log_dir)
        .map_err(|e| format!("创建日志文件失败: {e}"))
}
