//! 桌面端特有的宿主行为——与连接编排无关，只关心这台机器上的窗口与控制台。

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(dw_process_id: u32) -> i32;
    fn AllocConsole() -> i32;
}

/// 开发者模式下把 stdout/stderr 接到一个可见的控制台。
///
/// Tauri 的 Windows 产物是 GUI 子系统程序，默认没有控制台，`println!`
/// 与 tracing 的 stdout 输出会直接进黑洞。开发者模式需要看到它们。
#[cfg(windows)]
pub fn enable_dev_console(dev_mode: bool) {
    if !dev_mode {
        return;
    }

    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;

    // 优先附着父进程控制台；若不存在（例如双击启动），则新建一个控制台窗口。
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let _ = AllocConsole();
        }
    }
}

#[cfg(not(windows))]
pub fn enable_dev_console(_dev_mode: bool) {}

/// 客户端日志目录。
///
/// 与启动时 `logging::init` 用的是同一处，"打包整个目录上报"才对得上。
/// 优先放在安装目录（便携部署好找），不可写时退回用户数据目录。
///
/// **不要换成 `phantom_core::runtime::default_log_directory()`**——那个走的是
/// 配置目录，换过去会让老用户的日志集体搬家。
pub fn client_log_dir() -> std::path::PathBuf {
    let install = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .filter(|dir| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(".write-probe"))
                .is_ok()
        });
    match install {
        Some(dir) => dir.join("log"),
        None => dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("phantom-p2p")
            .join("log"),
    }
}
