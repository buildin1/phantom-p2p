//! 幻梦P2P 客户端 — Tauri 桌面宿主
//!
//! 连接编排（信令 → NAT 探测 → 三阶段打洞 → 建隧道 → 中继回退）住在
//! `phantom_core::runtime::SessionRuntime`，桌面端、headless 端与 Android
//! 共用同一份。本文件只剩桌面宿主该管的事：
//!
//! - `desktop`  → 开发者控制台、日志与数据目录
//! - `net_diag` → NAT 诊断页（桌面独有）
//! - `config`   → 配置读写命令
//! - 以及把前端的 `invoke` 转交给运行时

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};

mod config;
mod desktop;
mod net_diag;
use phantom_core::network_info;
use phantom_core::runtime::{RuntimeHost, SessionRuntime};

// Web 服务器模块（仅在启用 web-server feature 时编译）
#[cfg(feature = "web-server")]
pub mod web_server;

/// 全局开发者模式标志（定义于 phantom_core，此处直接使用）
use phantom_core::DEV_MODE;

/// 桌面端的 [`RuntimeHost`] 实现。
///
/// 连接编排全部住在 `phantom_core::runtime`，三端共用；桌面端只回答宿主特有的
/// 三个问题：事件怎么送给界面、日志写哪、数据放哪。
struct TauriHost {
    app: AppHandle,
}

impl RuntimeHost for TauriHost {
    fn emit(&self, event: &str, data: serde_json::Value) {
        let _ = self.app.emit(event, data);
    }

    /// **不能用 core 的默认实现**：桌面端的日志优先落在安装目录（便携部署好找），
    /// 不可写才退回用户数据目录。换成配置目录会让老用户的日志集体搬家。
    fn log_dir(&self) -> std::path::PathBuf {
        desktop::client_log_dir()
    }

    /// 同样不能用默认实现：设备身份密钥一直存在这里。换目录会让
    /// `Identity::load_or_generate` 生成新密钥，所有老用户的 user_id 全变。
    fn data_dir(&self) -> std::path::PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("phantom-p2p")
    }
}

/// Tauri 管理的运行时句柄。
///
/// 取代了原先的 `SignalState` / `PunchState` / `StatsState` 三件套——
/// 那十几个各自加锁的字段现在是 `SessionRuntime` 内部的单个状态机。
struct AppRuntime {
    runtime: Arc<SessionRuntime>,
}

/// 把命令转交给共享运行时。
///
/// 前端的调用契约（命令名、参数名、返回值）保持不变，变的只是它背后
/// 由谁执行。
async fn forward(
    state: &tauri::State<'_, AppRuntime>,
    command: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, String> {
    state.runtime.invoke(command, payload).await
}

// ============================================================
// Tauri 命令
// ============================================================

/// 查询是否为开发者模式。
///
/// 不走 `invoke`：core 的实现对 headless 端恒为 false，桌面端要读真实标志。
#[tauri::command]
fn is_dev_mode() -> bool {
    DEV_MODE.load(Ordering::Relaxed)
}

#[tauri::command]
fn show_main_window(window: tauri::WebviewWindow) {
    let _ = window.show();
}

/// 主动上报日志（前端"反馈问题"按钮调用）。
///
/// 只是向服务端要一个一次性上传凭据；真正的打包与上传在收到
/// `RequestLogUpload` 后进行。
#[tauri::command]
async fn report_problem(state: tauri::State<'_, AppRuntime>, reason: String) -> Result<(), String> {
    state.runtime.request_log_upload(reason).await
}

/// 连接信令服务器。
#[tauri::command]
async fn connect_signal(
    signal_url: String,
    state: tauri::State<'_, AppRuntime>,
) -> Result<(), String> {
    let url = config::runtime_signal_server(&signal_url);
    // auto_host 为 false：桌面端由用户决定何时建房，不自动创建。
    state.runtime.connect_signal(url).await;
    Ok(())
}

#[tauri::command]
async fn disconnect_signal(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "disconnect_signal", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn get_signal_status(
    state: tauri::State<'_, AppRuntime>,
) -> Result<serde_json::Value, String> {
    forward(&state, "get_signal_status", serde_json::Value::Null).await
}

#[tauri::command]
async fn create_room(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "create_room", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn join_room(room_code: String, state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(
        &state,
        "join_room",
        serde_json::json!({ "roomCode": room_code }),
    )
    .await?;
    Ok(())
}

#[tauri::command]
async fn leave_room(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "leave_room", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn close_room(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "close_room", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn request_fixed_host_ip(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "request_fixed_host_ip", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn release_fixed_host_ip(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "release_fixed_host_ip", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn get_fixed_host_ip(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "get_fixed_host_ip", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn start_punch(
    peer_session_id: Option<String>,
    state: tauri::State<'_, AppRuntime>,
) -> Result<(), String> {
    forward(
        &state,
        "start_punch",
        serde_json::json!({ "peer_session_id": peer_session_id }),
    )
    .await?;
    Ok(())
}

#[tauri::command]
async fn request_relay(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "request_relay", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn start_relay_tunnel(
    relay_addr: String,
    relay_quic_port: u16,
    token: String,
    state: tauri::State<'_, AppRuntime>,
) -> Result<(), String> {
    forward(
        &state,
        "start_relay_tunnel",
        serde_json::json!({
            "relayAddr": relay_addr,
            "relayQuicPort": relay_quic_port,
            "token": token,
        }),
    )
    .await?;
    Ok(())
}

#[tauri::command]
async fn start_tun_bridge(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "start_tun_bridge", serde_json::Value::Null).await?;
    Ok(())
}

#[tauri::command]
async fn get_tunnel_stats(
    state: tauri::State<'_, AppRuntime>,
) -> Result<serde_json::Value, String> {
    forward(&state, "get_tunnel_stats", serde_json::Value::Null).await
}

#[tauri::command]
async fn reset_tunnel_stats(state: tauri::State<'_, AppRuntime>) -> Result<(), String> {
    forward(&state, "reset_tunnel_stats", serde_json::Value::Null).await?;
    Ok(())
}

#[cfg(windows)]
fn ensure_admin() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // 已经是管理员则跳过
    if unsafe { IsUserAnAdmin() != 0 } {
        return;
    }

    // 获取当前 exe 路径
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };

    // 构建宽字符串参数
    let path_wide: Vec<u16> = OsStr::new(exe_path.as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let verb_wide: Vec<u16> = OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // 通过 ShellExecuteW 以管理员权限重新启动
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb_wide.as_ptr(),
            path_wide.as_ptr(),
            std::ptr::null(), // 无额外参数
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }

    // 退出当前（非管理员）进程
    std::process::exit(0);
}

/// 提取嵌入到 exe 中的 DLL 到可执行文件所在目录
///
/// wintun.dll 和 WebView2Loader.dll 通过 include_bytes! 嵌入到 exe 中，
/// 运行时自动提取，无需外部文件。
///
/// # 覆写策略
/// - wintun.dll：**始终覆写**，确保虚拟网卡驱动版本与当前程序匹配。
///   之前旧版 wintun.dll 因大小相同而跳过覆写的逻辑会导致启动时
///   加载到不兼容版本，无法找到 WintunCreateAdapter 函数。
/// - WebView2Loader.dll：仅当文件不存在或大小不同时覆写（较稳定，无需频繁更新）。
#[cfg(windows)]
fn extract_embedded_dlls() {
    use std::io::Write;

    // 获取可执行文件所在目录
    let exe_dir = match std::env::current_exe() {
        Ok(p) => p
            .parent()
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default()),
        Err(_) => return,
    };

    // 嵌入的 DLL 列表
    struct EmbeddedDll {
        filename: &'static str,
        data: &'static [u8],
        /// true = 始终覆写，false = 相同大小则跳过
        always_overwrite: bool,
    }

    let dlls = [
        EmbeddedDll {
            filename: "wintun.dll",
            data: include_bytes!("../../build/wintun.dll"),
            always_overwrite: true,
        },
        EmbeddedDll {
            filename: "WebView2Loader.dll",
            data: include_bytes!("../../build/WebView2Loader.dll"),
            always_overwrite: false,
        },
    ];

    for dll in &dlls {
        let dll_path = exe_dir.join(dll.filename);

        // 对于 always_overwrite = true 的 DLL：始终覆写
        // 对于其他 DLL：只有文件不存在或大小不同时才覆写
        let should_extract = if dll.always_overwrite {
            true
        } else if let Ok(meta) = std::fs::metadata(&dll_path) {
            meta.len() != dll.data.len() as u64
        } else {
            true
        };

        if !should_extract {
            continue;
        }

        match std::fs::File::create(&dll_path) {
            Ok(mut file) => {
                if file.write_all(dll.data).is_ok() {
                    tracing::debug!("[启动] 已提取 {}", dll.filename);
                } else {
                    tracing::warn!("[启动] 写入 {} 失败（不影响启动）", dll.filename);
                }
            }
            Err(e) => {
                // 提取失败不阻止启动
                tracing::warn!("[启动] 提取 {} 失败: {}（不影响启动）", dll.filename, e);
            }
        }
    }
}

// ============================================================
// 应用入口
// ============================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run(dev_mode: bool) {
    // Windows 需要以管理员身份运行整个进程才能创建 TUN 虚拟网卡（UAC）。
    // macOS 不这样做：root 权限的 Cocoa/WebView GUI 进程会卡顿且无法最大/
    // 最小化，因此改为仅在实际创建 utun 设备时，临时提权一个很小的独立
    // helper 进程（crates/macos-helper），见 crates/core/src/tun_macos.rs。
    #[cfg(windows)]
    ensure_admin();

    // 提取嵌入的 DLL（wintun.dll + WebView2Loader.dll）到可执行文件目录
    #[cfg(windows)]
    extract_embedded_dlls();

    // 限制 Tauri 异步运行时的 worker 线程数，避免与游戏进程争抢所有 CPU 核心。
    // 2 条线程足够处理 P2P 隧道 I/O，同时为游戏保留剩余核心。
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Tokio 运行时初始化失败");
    tauri::async_runtime::set(rt.handle().clone());

    DEV_MODE.store(dev_mode, Ordering::Relaxed);

    #[cfg(windows)]
    desktop::enable_dev_console(dev_mode);

    // 初始化 Rustls 加密提供者
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // 初始化日志
    let default_filter = "phantom_p2p_lib=debug,phantom_core=debug";

    let app_data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("phantom-p2p");
    let install_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf));
    // 日志按用途分文件（ice / signal / tunnel / app）并按大小轮转。
    // 旧实现是单个 phantom-p2p.log：实测 8 小时会话 48,736 行 / 6 MB，
    // 其中 91.4% 是每秒一条、数值相同的心跳 DEBUG，
    // 真正有用的打洞过程被完全淹没，也没法上报给服务端做聚合。
    let _ = install_dir;
    let log_dir = desktop::client_log_dir();
    let _ = std::env::var("RUST_LOG").or_else(|_| {
        std::env::set_var("RUST_LOG", default_filter);
        Ok::<String, std::env::VarError>(default_filter.to_string())
    });
    if let Err(e) = phantom_core::logging::init(&log_dir, dev_mode) {
        eprintln!("[日志] 分层日志初始化失败，仅输出到控制台: {}", e);
    }

    if dev_mode {
        tracing::info!("[DEV] 开发者模式已启用");
    }

    let _ = app_data_dir;

    tauri::Builder::default()
        .setup(move |_app| {
            // WebView2 已就绪后再降低进程优先级，避免影响 WebView2 子进程初始化速度
            #[cfg(windows)]
            unsafe {
                let handle = windows_sys::Win32::System::Threading::GetCurrentProcess();
                windows_sys::Win32::System::Threading::SetPriorityClass(
                    handle,
                    windows_sys::Win32::System::Threading::BELOW_NORMAL_PRIORITY_CLASS,
                );
            }

            // 运行时要在这里才能建：它需要 AppHandle 才能把事件发给界面。
            // 身份密钥、信令客户端与统计采样都由 SessionRuntime 内部完成，
            // 不再在此处各建一份。
            let host = Arc::new(TauriHost {
                app: _app.handle().clone(),
            });
            let runtime = SessionRuntime::new(host).map_err(|e| {
                tracing::error!("[启动] 运行时初始化失败: {}", e);
                e
            })?;
            _app.manage(AppRuntime { runtime });

            // 启动时静默检测一次出口公网 IP 对应的宽带运营商（纯展示型功能，
            // 不阻塞 UI，失败也不打断用户，只记日志）。
            let app_for_isp = _app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match network_info::detect_local_isp().await {
                    Ok(info) => {
                        tracing::info!(
                            "[网络信息] 检测到出口 IP={} ISP={}",
                            info.public_ip,
                            info.isp
                        );
                        let _ = app_for_isp.emit("network:isp_detected", info);
                    }
                    Err(e) => {
                        tracing::warn!("[网络信息] 检测运营商失败: {}", e);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            show_main_window,
            is_dev_mode,
            net_diag::get_network_info,
            connect_signal,
            disconnect_signal,
            get_signal_status,
            create_room,
            request_fixed_host_ip,
            release_fixed_host_ip,
            get_fixed_host_ip,
            join_room,
            leave_room,
            close_room,
            start_punch,
            start_relay_tunnel,
            start_tun_bridge,
            request_relay,
            get_tunnel_stats,
            reset_tunnel_stats,
            report_problem,
            config::load_config,
            config::save_config,
            config::get_config_path,
        ])
        .run(tauri::generate_context!())
        .expect("启动 Tauri 应用失败");
}
