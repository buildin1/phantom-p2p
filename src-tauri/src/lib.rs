//! 幻梦P2P 客户端 — Tauri 应用核心
//!
//! 模块：
//! - nat/    → NAT 检测（STUN、UPnP、IPv6）
//! - signal/ → 信令客户端（WebSocket）
//! - puncher → UDP 打洞引擎

use phantom_protocol::{ClientMessage, IceCandidate, RelayPreAllocInfo, ServerMessage};
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};

mod config;
use phantom_core::{
    identity, nat, network, network_info, punch, puncher, signal, stats, stun, tun_bridge, tunnel,
};
use std::sync::atomic::AtomicBool;

// Web 服务器模块（仅在启用 web-server feature 时编译）
#[cfg(feature = "web-server")]
pub mod web_server;

/// 全局开发者模式标志（定义于 phantom_core，此处直接使用）
use phantom_core::DEV_MODE;

/// 信令客户端全局状态（通过 Tauri State 管理）
struct SignalState {
    client: Arc<signal::client::SignalClient>,
}

struct HostPeer {
    socket: Arc<UdpSocket>,
    endpoint: Option<quinn::Endpoint>,
}

/// 客户端日志目录。
///
/// 与启动时 `logging::init` 用的是同一处，"打包整个目录上报"才对得上。
/// 优先放在安装目录（便携部署好找），不可写时退回用户数据目录。
fn client_log_dir() -> std::path::PathBuf {
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

/// 主动上报日志（前端"反馈问题"按钮调用）。
///
/// 只是向服务端要一个一次性上传凭据；真正的打包与上传在收到
/// `RequestLogUpload` 后进行。
#[tauri::command]
async fn report_problem(
    signal_state: tauri::State<'_, SignalState>,
    reason: String,
) -> Result<(), String> {
    signal_state
        .client
        .send(ClientMessage::RequestLogUpload { reason })
        .await
}

/// 打洞会话的键：Guest 端只有一个对端（Host），Host 端按 Guest 区分
fn punch_session_key(is_host: bool, peer_session_id: &str) -> String {
    if is_host {
        peer_session_id.to_string()
    } else {
        "__host__".to_string()
    }
}

/// 取服务端下发的 STUN 列表（自建优先）。
///
/// 客户端不内置任何 STUN 地址——公共 STUN 不可用时会直接导致
/// 拿不到 srflx 候选，进而必然落中继。
async fn stun_servers_from(client: &Arc<signal::client::SignalClient>) -> Vec<(String, u16)> {
    match client.network_config().await {
        Some(cfg) => cfg
            .stun_servers
            .iter()
            .map(|s| (s.host.clone(), s.port))
            .collect(),
        None => {
            tracing::warn!("[打洞] 服务端尚未下发 STUN 配置");
            Vec::new()
        }
    }
}

/// 打洞状态（通过 Tauri State 管理）
struct PunchState {
    /// 当前打洞用的 UDP socket（STUN 探测和打洞共用）
    socket: tokio::sync::Mutex<Option<Arc<UdpSocket>>>,
    /// 当前打洞任务句柄（用于切房/离房时取消旧任务）
    punch_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 是否为 Host（创建房间的一方）
    is_host: tokio::sync::RwLock<bool>,
    /// 本端收集的 ICE 候选（阶段一探测后存入）
    local_ice_candidates: tokio::sync::Mutex<Vec<IceCandidate>>,
    /// 打洞会话：Guest 端键为 `__host__`，Host 端每个 Guest 一个。
    /// 三阶段状态机在 phantom-core，两个客户端共用同一份实现。
    punch_sessions: tokio::sync::Mutex<std::collections::HashMap<String, punch::Session>>,
    /// 打洞阶段协商出的 overlay 会话密钥。
    /// P2P 与中继两条路径共用同一份——中继只做盲转发，看不到明文。
    peer_crypto: tokio::sync::Mutex<Option<Arc<phantom_core::crypto::SessionCrypto>>>,
    /// 预分配的中继信息（RelayPreAllocated 到达时存入）
    relay_prealloc: tokio::sync::Mutex<Option<RelayPreAllocInfo>>,
    /// Guest 侧隧道连接管理器（支持静默升级）
    conn_manager: tokio::sync::Mutex<Option<Arc<tunnel::TunnelConnManager>>>,
    /// ICE 打洞任务句柄（ICE 连通性检测中）
    ice_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    host_ice_tasks:
        tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Host 侧 QUIC Endpoint（多 guest 共享同一 endpoint，避免 reset 时销毁已建立连接）
    host_endpoint: tokio::sync::Mutex<Option<quinn::Endpoint>>,
    host_peers: tokio::sync::Mutex<std::collections::HashMap<String, HostPeer>>,
    /// One long-lived Host relay connection serves every Guest in the room.
    relay_host_token: tokio::sync::Mutex<Option<String>>,
    relay_host_conn: tokio::sync::Mutex<Option<quinn::Connection>>,
    /// TUN ↔ QUIC 桥接器（虚拟网卡）
    tun_bridge: tokio::sync::Mutex<Option<Arc<tun_bridge::TunBridge>>>,
    /// 当前房间的子网前缀（如 "10.0.1"）
    subnet: tokio::sync::RwLock<String>,
    /// 本机和 Host 的信令分配虚拟地址
    virtual_ip: tokio::sync::RwLock<String>,
    host_virtual_ip: tokio::sync::RwLock<String>,
    /// 是否启用了 TUN 设备（防止重复启停）
    tun_enabled: AtomicBool,
}

/// 统计状态（通过 Tauri State 管理）
struct StatsState {
    manager: Arc<stats::StatsManager>,
}

/// 风控自校准库的持有者。
///
/// 单独 manage 出来，是为了让打洞成功、拿到本端公网 IP 和 NAT 类型之后，
/// 能把库和"这个网络环境的指纹"一起绑到那条连接的 `LinkSignals` 上。
struct CalibrationState {
    store: Arc<phantom_core::repair::CalibrationStore>,
}

/// 网络诊断信息
#[derive(Serialize, Deserialize)]
pub struct NetworkInfo {
    pub nat_type: String,
    pub nat_type_key: String,
    pub nat_difficulty: String,
    pub external_ip: String,
    pub external_port: u16,
    pub upnp: bool,
    pub upnp_port: u16,
    pub ipv6: bool,
    pub ipv6_addr: String,
    pub local_ip: String,
    pub local_port: u16,
    pub stun_mappings: Vec<String>,
    pub stun_details: Vec<StunDetail>,
    pub port_pattern: String,
    pub mapping_behavior: String,
    pub filtering_behavior: String,
    pub confidence: String,
    pub diagnostics_rounds: u8,
    pub network_priority: String,
}

#[derive(Serialize, Deserialize)]
pub struct StunDetail {
    pub server: String,
    pub mapping: String,
    pub rtt_ms: u32,
    pub socket: String,
    pub round: u8,
}

#[derive(Serialize, Clone)]
struct NetDiagProgress {
    progress: u8,
    stage: String,
    eta_seconds: u8,
}

/// 前端展示的连接信息
#[derive(Debug, Clone, Serialize)]
pub struct SignalStatus {
    pub state: String,
    pub session_id: Option<String>,
    pub room_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TunnelFailedPayload {
    mode: String,
    reason: String,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(dw_process_id: u32) -> i32;
    fn AllocConsole() -> i32;
}

#[cfg(windows)]
fn enable_windows_dev_console(dev_mode: bool) {
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

async fn abort_punch_task(punch_state: &PunchState) {
    if let Some(handle) = punch_state.punch_task.lock().await.take() {
        handle.abort();
    }
    if let Some(handle) = punch_state.ice_task.lock().await.take() {
        handle.abort();
    }
    for (_, handle) in std::mem::take(&mut *punch_state.host_ice_tasks.lock().await) {
        handle.abort();
    }
}

async fn reset_connection_runtime(punch_state: &PunchState) {
    abort_punch_task(punch_state).await;
    *punch_state.socket.lock().await = None;
    *punch_state.local_ice_candidates.lock().await = Vec::new();
    *punch_state.relay_prealloc.lock().await = None;
    // 会话密钥与本轮打洞绑定，重置时必须一并清掉——
    // 复用上一轮的密钥会导致 nonce 计数器与对端不一致
    punch_state.punch_sessions.lock().await.clear();
    *punch_state.peer_crypto.lock().await = None;
    if let Some(mgr) = punch_state.conn_manager.lock().await.take() {
        mgr.close().await;
    }
    if let Some(ep) = punch_state.host_endpoint.lock().await.take() {
        ep.close(0u32.into(), b"");
    }
    for (_, peer) in std::mem::take(&mut *punch_state.host_peers.lock().await) {
        if let Some(endpoint) = peer.endpoint {
            endpoint.close(0u32.into(), b"room connection reset");
        }
    }
    *punch_state.relay_host_token.lock().await = None;
    if let Some(conn) = punch_state.relay_host_conn.lock().await.take() {
        conn.close(0u32.into(), b"room connection reset");
    }
}

async fn reset_punch_runtime(punch_state: &PunchState) {
    reset_connection_runtime(punch_state).await;
    if let Some(bridge) = punch_state.tun_bridge.lock().await.take() {
        bridge.close().await;
    }
    punch_state
        .tun_enabled
        .store(false, std::sync::atomic::Ordering::Relaxed);
}

async fn clear_virtual_network(punch_state: &PunchState) {
    *punch_state.subnet.write().await = String::new();
    *punch_state.virtual_ip.write().await = String::new();
    *punch_state.host_virtual_ip.write().await = String::new();
}

// ============================================================
// Tauri 命令
// ============================================================

/// 查询是否为开发者模式
#[tauri::command]
fn is_dev_mode() -> bool {
    DEV_MODE.load(Ordering::Relaxed)
}

/// 获取网络信息（NAT 类型、公网 IP、STUN、UPnP、IPv6 等）
#[tauri::command]
async fn get_network_info(app: AppHandle) -> Result<NetworkInfo, String> {
    const DIAG_ROUNDS: usize = 3;
    let emit_progress = |progress: u8, stage: &str, eta_seconds: u8| {
        let _ = app.emit(
            "diag:progress",
            NetDiagProgress {
                progress,
                stage: stage.to_string(),
                eta_seconds,
            },
        );
    };

    emit_progress(4, "初始化诊断环境", 15);

    let mut rounds = Vec::with_capacity(DIAG_ROUNDS);
    for idx in 0..DIAG_ROUNDS {
        let progress = 10 + (idx as u8 * 20);
        let eta = ((DIAG_ROUNDS - idx) * 4 + 3) as u8;
        emit_progress(
            progress,
            &format!("多 STUN 映射采样 第 {}/{} 轮", idx + 1, DIAG_ROUNDS),
            eta,
        );
        rounds.push(stun::query_dual_async().await);
    }

    emit_progress(72, "过滤行为探测（IP/端口限制）", 5);
    let filtering_probe = stun::detect_filtering_behavior_async().await;

    let analysis = nat::analyze_multi_round(
        &rounds,
        filtering_probe.behavior.key(),
        &format!("{} @ {}", filtering_probe.detail, filtering_probe.server),
    );

    let mut merged_a = Vec::new();
    let mut merged_b = Vec::new();
    let mut stun_details: Vec<StunDetail> = Vec::new();
    for (round_index, round) in rounds.iter().enumerate() {
        merged_a.extend(round.mappings_a.clone());
        merged_b.extend(round.mappings_b.clone());

        for sample in &round.samples_a {
            stun_details.push(StunDetail {
                server: sample.server.clone(),
                mapping: format!("{}:{}", sample.mapping.ip, sample.mapping.port),
                rtt_ms: sample.rtt_ms,
                socket: "A".to_string(),
                round: (round_index + 1) as u8,
            });
        }
        for sample in &round.samples_b {
            stun_details.push(StunDetail {
                server: sample.server.clone(),
                mapping: format!("{}:{}", sample.mapping.ip, sample.mapping.port),
                rtt_ms: sample.rtt_ms,
                socket: "B".to_string(),
                round: (round_index + 1) as u8,
            });
        }
    }

    let primary = if !merged_a.is_empty() {
        &merged_a
    } else {
        &merged_b
    };
    let (external_ip, external_port) = if let Some(first) = primary.first() {
        (first.ip.clone(), first.port)
    } else {
        ("0.0.0.0".to_string(), 0)
    };
    let local_port = rounds.first().map(|r| r.local_port_a).unwrap_or(0);

    let mut stun_mappings: Vec<String> = Vec::new();
    for detail in &stun_details {
        stun_mappings.push(format!(
            "R{}-{}→{}",
            detail.round, detail.socket, detail.mapping
        ));
    }

    emit_progress(86, "UPnP / IPv6 / 本机网卡检测", 2);
    let (upnp_result, local_net) = tokio::join!(
        network::detect_upnp(),
        tokio::task::spawn_blocking(network::detect_local_network),
    );

    let local_net = local_net.unwrap_or_else(|_| network::LocalNetworkInfo {
        local_ip: "127.0.0.1".to_string(),
        ipv6_available: false,
        ipv6_addr: String::new(),
    });

    let network_priority = if local_net.ipv6_available {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    };

    emit_progress(95, "汇总 NAT 诊断结果", 1);

    let info = NetworkInfo {
        nat_type: analysis.nat_type.display_name().to_string(),
        nat_type_key: analysis.nat_type.type_key().to_string(),
        nat_difficulty: analysis.nat_type.difficulty().to_string(),
        mapping_behavior: analysis.mapping_behavior,
        filtering_behavior: analysis.filtering_behavior,
        confidence: analysis.confidence,
        external_ip,
        external_port,
        upnp: upnp_result.available,
        upnp_port: upnp_result.external_port,
        ipv6: local_net.ipv6_available,
        ipv6_addr: local_net.ipv6_addr,
        local_ip: local_net.local_ip,
        local_port,
        stun_mappings,
        stun_details,
        port_pattern: analysis.port_pattern,
        diagnostics_rounds: DIAG_ROUNDS as u8,
        network_priority,
    };

    emit_progress(100, "诊断完成", 0);
    Ok(info)
}

/// 连接信令服务器
#[tauri::command]
async fn connect_signal(
    signal_url: String,
    app: AppHandle,
    state: tauri::State<'_, SignalState>,
    _punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    let client = &state.client;
    let effective_signal_url = config::runtime_signal_server(&signal_url);

    // 如果已经连接，先断开
    let current = client.get_state().await;
    if current != signal::client::ConnectionState::Disconnected {
        client.disconnect().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // 连接
    client.connect(effective_signal_url).await;

    // 启动事件转发循环（将服务端消息推送到前端）
    if let Some(mut event_rx) = client.take_event_rx().await {
        let app_handle = app.clone();
        let client_clone = client.clone();
        let stats_mgr = stats_state.manager.clone();
        let app_for_task = app.clone();

        tokio::spawn(async move {
            while let Some(server_msg) = event_rx.recv().await {
                let event_name = match &server_msg {
                    ServerMessage::Welcome { .. } => "signal:welcome",
                    ServerMessage::Pong { .. } => "signal:pong",
                    ServerMessage::VersionMismatch { .. } => "signal:version_mismatch",
                    ServerMessage::NetworkConfigUpdate { .. } => "signal:network_config",
                    ServerMessage::RoomCreated { .. } => "signal:room_created",
                    ServerMessage::JoinOk { .. } => "signal:join_ok",
                    ServerMessage::JoinFailed { .. } => "signal:join_failed",
                    ServerMessage::PeerJoined { .. } => "signal:peer_joined",
                    ServerMessage::PeerLeft { .. } => "signal:peer_left",
                    ServerMessage::RoomClosed { .. } => "signal:room_closed",
                    ServerMessage::Error { .. } => "signal:error",
                    ServerMessage::AuthChallenge { .. } => "signal:auth_challenge",
                    ServerMessage::AuthOk { .. } => "signal:auth_ok",
                    ServerMessage::FixedHostIpStatus { .. } => "signal:fixed_host_ip_status",
                    ServerMessage::AuthFailed { .. } => "signal:auth_failed",
                    ServerMessage::RelayReady { .. } => "signal:relay_ready",
                    ServerMessage::RelayPreAllocated { .. } => "signal:relay_pre_allocated",
                    ServerMessage::PunchPlan { .. } => "signal:punch_plan",
                    ServerMessage::PunchStart { .. } => "signal:punch_start",
                    ServerMessage::RequestLogUpload { .. } => "signal:request_log_upload",
                };

                if let Ok(json_value) = serde_json::to_value(&server_msg) {
                    let _ = app_handle.emit(event_name, json_value);
                }

                match &server_msg {
                    ServerMessage::RoomCreated {
                        subnet, virtual_ip, ..
                    } => {
                        let ps = app_for_task.state::<PunchState>();
                        *ps.subnet.write().await = subnet.clone();
                        *ps.virtual_ip.write().await = virtual_ip.clone();
                        *ps.host_virtual_ip.write().await = virtual_ip.clone();
                        if let Some(old) = ps.tun_bridge.lock().await.take() {
                            old.close().await;
                        }
                        if let Some(old) = ps.conn_manager.lock().await.take() {
                            old.close().await;
                        }
                        if let Some(old) = ps.host_endpoint.lock().await.take() {
                            old.close(0u32.into(), b"Host address changed");
                        }
                        for (_, peer) in std::mem::take(&mut *ps.host_peers.lock().await) {
                            if let Some(endpoint) = peer.endpoint {
                                endpoint.close(0u32.into(), b"Host address changed");
                            }
                        }
                        ps.tun_enabled.store(false, Ordering::Relaxed);
                        match tun_bridge::TunBridge::start_host(subnet, virtual_ip).await {
                            Ok(bridge) => {
                                *ps.tun_bridge.lock().await = Some(bridge);
                                ps.tun_enabled.store(true, Ordering::Relaxed);
                                let _ = app_for_task.emit(
                                    "tun:ready",
                                    serde_json::json!({
                                        "my_ip": virtual_ip,
                                        "host_ip": virtual_ip,
                                        "subnet": subnet,
                                    }),
                                );
                                if let Err(e) = client_clone.send(ClientMessage::HostReady).await {
                                    tracing::error!(
                                        "[TUN] failed to announce Host readiness: {}",
                                        e
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!("[TUN] Host 虚拟网卡启动失败: {}", e);
                                let _ = app_for_task.emit("tun:failed", e.to_string());
                                let _ = client_clone.send(ClientMessage::CloseRoom).await;
                            }
                        }
                        tracing::info!("[信令] RoomCreated: subnet={}, ip={}", subnet, virtual_ip);
                    }
                    ServerMessage::JoinOk {
                        subnet,
                        virtual_ip,
                        host_virtual_ip,
                        ..
                    } => {
                        let ps = app_for_task.state::<PunchState>();
                        *ps.subnet.write().await = subnet.clone();
                        *ps.virtual_ip.write().await = virtual_ip.clone();
                        *ps.host_virtual_ip.write().await = host_virtual_ip.clone();
                        tracing::info!(
                            "[信令] JoinOk: subnet={}, ip={}, host={}",
                            subnet,
                            virtual_ip,
                            host_virtual_ip
                        );
                    }
                    ServerMessage::PeerLeft {
                        peer_session_id, ..
                    } => {
                        let ps = app_for_task.state::<PunchState>();
                        if let Some(task) = ps.host_ice_tasks.lock().await.remove(peer_session_id) {
                            task.abort();
                        }
                        let removed_peer = { ps.host_peers.lock().await.remove(peer_session_id) };
                        if let Some(peer) = removed_peer {
                            if let Some(endpoint) = peer.endpoint {
                                endpoint.close(0u32.into(), b"peer left");
                            }
                        }
                    }
                    // 收到上传凭据：打包整个 log/ 目录并上传。
                    // 打包与 HTTP 传输都是阻塞操作，放到 blocking 线程池，
                    // 避免拖住信令消息循环。
                    ServerMessage::RequestLogUpload { upload_url, reason } => {
                        let url = upload_url.clone();
                        let why = reason.clone();
                        let app_for_upload = app_for_task.clone();
                        tokio::task::spawn_blocking(move || {
                            let dir = client_log_dir();
                            let uploader = phantom_core::log_upload::LogUploader::new(&dir);
                            // 先补投历史失败的包——它们往往正是"网络有问题"那次的日志
                            uploader.flush_pending();
                            match uploader.upload_now(&url, &why) {
                                Ok(bytes) => {
                                    tracing::info!("[日志上报] 已上传 {} 字节", bytes);
                                    let _ = app_for_upload.emit("log:uploaded", bytes);
                                }
                                Err(e) => {
                                    tracing::warn!("[日志上报] {}", e);
                                    let _ = app_for_upload.emit("log:upload_failed", e);
                                }
                            }
                        });
                    }
                    ServerMessage::RelayPreAllocated {
                        room_code,
                        relay_addr,
                        relay_quic_port,
                        token,
                    } => {
                        let prealloc = RelayPreAllocInfo {
                            room_code: room_code.clone(),
                            relay_addr: relay_addr.clone(),
                            token: token.clone(),
                        };
                        let ps = app_for_task.state::<PunchState>();
                        *ps.relay_prealloc.lock().await = Some(prealloc);
                        tracing::info!("[ICE] 中继预分配就绪 (QUIC port={})", relay_quic_port);
                    }
                    // ── 阶段二：收到策略计划，按需新建 socket 并回报候选 ──
                    ServerMessage::PunchPlan {
                        peer_session_id,
                        attempt_id,
                        strategy,
                        params,
                        peer_profile,
                        ..
                    } => {
                        let ps = app_for_task.state::<PunchState>();
                        let is_host = *ps.is_host.read().await;
                        let key = punch_session_key(is_host, peer_session_id);
                        let stun = stun_servers_from(&client_clone).await;

                        let extra = {
                            let mut sessions = ps.punch_sessions.lock().await;
                            match sessions.get_mut(&key) {
                                // Host 恒为 initiator：双方必须得出相反的角色，
                                // 否则会各自用同一把密钥发送，导致 nonce 复用
                                Some(s) => s.on_plan(
                                    attempt_id.clone(),
                                    *strategy,
                                    *params,
                                    peer_profile.clone(),
                                    &stun,
                                    is_host,
                                ),
                                None => {
                                    tracing::warn!("[打洞] 收到计划但会话不存在: {}", key);
                                    Vec::new()
                                }
                            }
                        };

                        if !extra.is_empty() {
                            let _ = client_clone
                                .send(ClientMessage::StrategyCandidates {
                                    target_peer_session_id: peer_session_id.clone(),
                                    attempt_id: attempt_id.clone(),
                                    candidates: extra,
                                })
                                .await;
                        }
                    }
                    // ── 阶段三：统一起始时刻，执行打洞 ──────────────
                    ServerMessage::PunchStart {
                        peer_session_id,
                        peer_candidates,
                        start_delay_ms,
                        ..
                    } => {
                        let app_for_ice = app_for_task.clone();
                        let peer_session_id = peer_session_id.clone();
                        let task_peer_id = peer_session_id.clone();
                        let candidates = peer_candidates.clone();
                        let start_delay_ms = *start_delay_ms;
                        let stats_for_ice = stats_mgr.clone();
                        let signal_client_for_ice = client_clone.clone();

                        let ice_task = tokio::spawn(async move {
                            let ps = app_for_ice.state::<PunchState>();
                            let is_host = *ps.is_host.read().await;
                            let key = punch_session_key(is_host, &peer_session_id);

                            let mut session = {
                                let mut sessions = ps.punch_sessions.lock().await;
                                match sessions.remove(&key) {
                                    Some(s) => s,
                                    None => {
                                        let _ = app_for_ice.emit(
                                            "punch:phase",
                                            puncher::PunchPhase::Failed {
                                                reason: "打洞会话未就绪".into(),
                                            },
                                        );
                                        return;
                                    }
                                }
                            };

                            // 开发者模式的强制中继：会话密钥在阶段二 `on_plan` 就已经
                            // 通过双方交换的临时公钥派生完毕，跟真的去打洞完全无关——
                            // 这里直接跳过 `session.run()`（真实 UDP 打洞尝试），把它当成
                            // 一次打洞失败处理，复用前端已有的"失败就回退中继"路径。
                            // 这样强制中继复用的是跟正常中继回退完全相同的代码，
                            // 不需要另起一套中继连接逻辑。
                            if crate::DEV_MODE.load(Ordering::Relaxed)
                                && phantom_core::config::ClientConfig::load().force_relay_mode
                            {
                                *ps.peer_crypto.lock().await = session.crypto();
                                tracing::warn!("[开发者模式] 强制中继已开启，跳过 P2P 打洞");
                                let _ = app_for_ice.emit(
                                    "punch:phase",
                                    puncher::PunchPhase::Failed {
                                        reason: "开发者模式已开启强制中继".into(),
                                    },
                                );
                                return;
                            }

                            let _ = app_for_ice.emit("punch:phase", puncher::PunchPhase::Punching);

                            let room_code = signal_client_for_ice
                                .get_room_code()
                                .await
                                .unwrap_or_default();
                            let ctx = punch::RecordContext::new(
                                room_code,
                                peer_session_id.clone(),
                                is_host,
                            );
                            let outcome = session.run(candidates, start_delay_ms, ctx).await;

                            // 成败都上报——失败样本对分析 NAT 组合成功率同样重要
                            let _ = signal_client_for_ice
                                .send(ClientMessage::PunchReport {
                                    record: outcome.record.clone(),
                                })
                                .await;

                            let result = match (&outcome.success, &outcome.socket) {
                                (Some(s), Some(_)) => puncher::PunchResult {
                                    success: true,
                                    peer_addr: s.peer_addr.to_string(),
                                    latency_ms: s.rtt_ms,
                                    reason: String::new(),
                                },
                                _ => puncher::PunchResult {
                                    success: false,
                                    peer_addr: String::new(),
                                    latency_ms: 0,
                                    reason: format!("{:?}", outcome.record.outcome),
                                },
                            };

                            // 数据面必须用这把密钥；没有它就只能明文，宁可不建隧道
                            *ps.peer_crypto.lock().await = outcome.crypto.clone();

                            // 打通的正是这个 socket 的映射，隧道必须复用它
                            let sock = match outcome.socket.clone() {
                                Some(s) => s,
                                None => {
                                    let _ = app_for_ice.emit(
                                        "punch:phase",
                                        puncher::PunchPhase::Failed {
                                            reason: result.reason.clone(),
                                        },
                                    );
                                    if is_host {
                                        if let Some(peer) =
                                            ps.host_peers.lock().await.remove(&peer_session_id)
                                        {
                                            if let Some(endpoint) = peer.endpoint {
                                                endpoint.close(0u32.into(), b"punch failed");
                                            }
                                        }
                                    }
                                    return;
                                }
                            };
                            if is_host {
                                if let Some(peer) =
                                    ps.host_peers.lock().await.get_mut(&peer_session_id)
                                {
                                    peer.socket = sock.clone();
                                }
                            } else {
                                *ps.socket.lock().await = Some(sock.clone());
                            }

                            if result.success {
                                let _ = app_for_ice.emit(
                                    "punch:phase",
                                    puncher::PunchPhase::Success {
                                        latency_ms: result.latency_ms,
                                    },
                                );

                                let user_id = peer_session_id.clone();
                                stats_for_ice
                                    .add_connection(user_id.clone(), "p2p".to_string())
                                    .await;
                                stats_for_ice.set_connection_mode(&user_id, "p2p").await;
                                // 顺便把最终连接模式上报给信令服务器，供管理面板展示
                                let _ = signal_client_for_ice
                                    .send(ClientMessage::ReportConnectionMode {
                                        mode: "p2p".to_string(),
                                    })
                                    .await;

                                let peer_socket_addr: std::net::SocketAddr = result
                                    .peer_addr
                                    .parse()
                                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

                                if is_host {
                                    // 多人模式：复用已有 QUIC Endpoint，避免每次新建
                                    let mut tunnel_ready = false;
                                    if let Ok(sock_std) = sock.try_clone() {
                                        if let Ok(endpoint) = tunnel::create_host_endpoint(sock_std)
                                        {
                                            let ep_for_task = endpoint.clone();
                                            let sf = stats_for_ice.clone();
                                            let peer_map = Arc::new(tokio::sync::Mutex::new(
                                                std::collections::HashMap::from([(
                                                    peer_socket_addr.to_string(),
                                                    user_id.clone(),
                                                )]),
                                            ));
                                            let tun = ps.tun_bridge.lock().await.clone();
                                            let crypto = ps.peer_crypto.lock().await.clone();
                                            tokio::spawn(async move {
                                                let _ = tunnel::start_host_tunnel(
                                                    ep_for_task,
                                                    sf,
                                                    peer_map,
                                                    tun,
                                                    crypto,
                                                )
                                                .await;
                                            });
                                            if let Some(peer) =
                                                ps.host_peers.lock().await.get_mut(&peer_session_id)
                                            {
                                                peer.endpoint = Some(endpoint);
                                            }
                                            tunnel_ready = true;
                                        }
                                    }
                                    if tunnel_ready {
                                        let _ = app_for_ice.emit("tunnel:started", "P2P");
                                    } else {
                                        let _ = app_for_ice.emit(
                                            "tunnel:failed",
                                            TunnelFailedPayload {
                                                mode: "P2P".into(),
                                                reason: "Host QUIC Endpoint 创建失败".into(),
                                            },
                                        );
                                    }
                                } else {
                                    let mut tunnel_error = "复制 ICE socket 失败".to_string();
                                    let mut tunnel_ready = false;
                                    if let Ok(sock_std) = sock.try_clone() {
                                        match tunnel::create_guest_connection(
                                            sock_std,
                                            peer_socket_addr,
                                        )
                                        .await
                                        {
                                            Ok(conn) => {
                                                let mgr = tunnel::TunnelConnManager::new(conn);
                                                let sf = stats_for_ice.clone();
                                                let uf = user_id.clone();
                                                match tunnel::start_guest_tunnel_managed(
                                                    mgr.clone(),
                                                    0,
                                                    0,
                                                    sf,
                                                    uf,
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        *ps.conn_manager.lock().await = Some(mgr);
                                                        tunnel_ready = true;
                                                    }
                                                    Err(error) => tunnel_error = error,
                                                }
                                            }
                                            Err(error) => tunnel_error = error,
                                        }
                                    }
                                    if tunnel_ready {
                                        let _ = app_for_ice.emit("tunnel:started", "P2P");
                                    } else {
                                        let _ = app_for_ice.emit(
                                            "tunnel:failed",
                                            TunnelFailedPayload {
                                                mode: "P2P".into(),
                                                reason: tunnel_error,
                                            },
                                        );
                                    }
                                }
                            } else {
                                if is_host {
                                    if let Some(peer) =
                                        ps.host_peers.lock().await.remove(&peer_session_id)
                                    {
                                        if let Some(endpoint) = peer.endpoint {
                                            endpoint.close(0u32.into(), b"ICE failed");
                                        }
                                    }
                                }
                                let _ = app_for_ice.emit(
                                    "punch:phase",
                                    puncher::PunchPhase::Failed {
                                        reason: result.reason,
                                    },
                                );
                            }
                        });

                        let ps = app_for_task.state::<PunchState>();
                        if *ps.is_host.read().await {
                            ps.host_ice_tasks
                                .lock()
                                .await
                                .insert(task_peer_id, ice_task);
                        } else {
                            *ps.ice_task.lock().await = Some(ice_task);
                        }
                    }
                    _ => {}
                }

                let status = SignalStatus {
                    state: format!("{}", client_clone.get_state().await),
                    session_id: client_clone.get_session_id().await,
                    room_code: client_clone.get_room_code().await,
                };
                let _ = app_handle.emit("signal:status", status);
            }
        });
    }

    Ok(())
}

#[tauri::command]
async fn disconnect_signal(
    state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    reset_punch_runtime(&punch_state).await;
    clear_virtual_network(&punch_state).await;
    stats_state.manager.clear().await;
    stats_state.manager.set_host_mode(false);
    state.client.disconnect().await;
    Ok(())
}

#[tauri::command]
async fn get_signal_status(state: tauri::State<'_, SignalState>) -> Result<SignalStatus, String> {
    let client = &state.client;
    Ok(SignalStatus {
        state: format!("{}", client.get_state().await),
        session_id: client.get_session_id().await,
        room_code: client.get_room_code().await,
    })
}

/// 创建房间
#[tauri::command]
async fn create_room(
    signal_state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    // 一次连接一份干净日志：把上一段会话归档，从空文件重新开始。
    // 排障时最费时间的一步一直是"从混了七八次连接的大文件里找出出问题的那次"。
    phantom_core::logging::begin_session("host");

    reset_punch_runtime(&punch_state).await;
    clear_virtual_network(&punch_state).await;
    // 标记为 Host
    *punch_state.is_host.write().await = true;
    stats_state.manager.clear().await;
    stats_state.manager.set_host_mode(true);

    signal_state.client.send(ClientMessage::CreateRoom).await
}

#[tauri::command]
async fn request_fixed_host_ip(state: tauri::State<'_, SignalState>) -> Result<(), String> {
    state.client.send(ClientMessage::RequestFixedHostIp).await
}

#[tauri::command]
async fn release_fixed_host_ip(state: tauri::State<'_, SignalState>) -> Result<(), String> {
    state.client.send(ClientMessage::ReleaseFixedHostIp).await
}

#[tauri::command]
async fn get_fixed_host_ip(state: tauri::State<'_, SignalState>) -> Result<(), String> {
    state.client.send(ClientMessage::GetFixedHostIp).await
}

/// 加入房间
#[tauri::command]
async fn join_room(
    room_code: String,
    signal_state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    // 一次连接一份干净日志，理由同 `create_room`。用房间码命名，
    // 用户说"我那次进 XXXXX 连不上"时能直接定位到对应的归档。
    phantom_core::logging::begin_session(&room_code);

    reset_punch_runtime(&punch_state).await;
    // 上一个房间的 subnet / virtual_ip 不能留：其余四个会改变房间归属的命令
    // （create/leave/close/disconnect）都清了，唯独这里漏了。正常路径下
    // JoinOk 会覆盖，但一旦 JoinRoom 被拒（永远等不到 JoinOk），后续任何
    // 读到这些残值的逻辑都会拿着旧房间的虚拟 IP 去建网卡。
    clear_virtual_network(&punch_state).await;
    // 标记为 Guest
    *punch_state.is_host.write().await = false;
    stats_state.manager.clear().await;
    stats_state.manager.set_host_mode(false);

    // 直接换房间（不点"离开"）时，服务端 session 上还挂着旧房间——新版
    // 服务端已改为隐式 leave-then-join，这里再显式发一次 LeaveRoom 是给
    // 旧版服务端的兼容垫底。不在任何房间时服务端会静默忽略，无副作用。
    let _ = signal_state.client.send(ClientMessage::LeaveRoom).await;

    signal_state
        .client
        .send(ClientMessage::JoinRoom { room_code })
        .await
}

/// 离开房间
#[tauri::command]
async fn leave_room(
    state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    reset_punch_runtime(&punch_state).await;
    clear_virtual_network(&punch_state).await;
    stats_state.manager.clear().await;
    stats_state.manager.set_host_mode(false);
    state.client.send(ClientMessage::LeaveRoom).await
}

/// 关闭房间（仅 host）
#[tauri::command]
async fn close_room(
    state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    reset_punch_runtime(&punch_state).await;
    clear_virtual_network(&punch_state).await;
    stats_state.manager.clear().await;
    stats_state.manager.set_host_mode(false);
    state.client.send(ClientMessage::CloseRoom).await
}

/// **阶段一**：探测 NAT 画像并上报，等待服务端下发策略计划。
///
/// 与旧实现的关键差别：此处**只产出 host + srflx 基础候选**。
/// 预测/撒网候选属于阶段二——那时才从服务端拿到对端的 NAT 类型，
/// 才谈得上"按 NAT 配对选择打洞方向"。旧实现在这里就把候选定死了，
/// 所以策略矩阵在旧时序下根本无法实现。
///
/// Host 多人优化：若 Host 已采集过候选，直接复用已有 socket + 候选，
/// 不再 reset 现有连接，保证已连接的 guest 不受影响。
#[tauri::command]
async fn start_punch(
    app: AppHandle,
    signal_state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
    peer_session_id: Option<String>,
) -> Result<(), String> {
    let client = &signal_state.client;
    let is_dev = DEV_MODE.load(Ordering::Relaxed);
    let is_host = *punch_state.is_host.read().await;

    if is_host {
        let peer_id = peer_session_id.ok_or("Host ICE requires peer_session_id")?;
        if punch_state.host_peers.lock().await.contains_key(&peer_id) {
            return Ok(());
        }
        let (profile, candidates, sock, session) = probe_for_punch(client, is_dev, &app).await?;
        punch_state.host_peers.lock().await.insert(
            peer_id.clone(),
            HostPeer {
                socket: sock,
                endpoint: None,
            },
        );
        punch_state
            .punch_sessions
            .lock()
            .await
            .insert(punch_session_key(true, &peer_id), session);
        client
            .send(ClientMessage::NatProfileReport {
                target_peer_session_id: Some(peer_id),
                profile,
                base_candidates: candidates,
            })
            .await?;
        let _ = app.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
        return Ok(());
    }

    // TUN belongs to the room and must survive connection setup/retries.
    reset_connection_runtime(&punch_state).await;

    let (profile, candidates, sock, session) = probe_for_punch(client, is_dev, &app).await?;

    *punch_state.socket.lock().await = Some(sock);
    *punch_state.local_ice_candidates.lock().await = candidates.clone();
    punch_state
        .punch_sessions
        .lock()
        .await
        .insert(punch_session_key(false, ""), session);

    client
        .send(ClientMessage::NatProfileReport {
            target_peer_session_id: None,
            profile,
            base_candidates: candidates,
        })
        .await?;

    let _ = app.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
    tracing::info!("[打洞] 已上报 NAT 画像，等待服务端下发策略...");
    Ok(())
}

/// 执行阶段一探测，返回 (画像, 基础候选, 主 socket, 会话)
async fn probe_for_punch(
    client: &Arc<signal::client::SignalClient>,
    is_dev: bool,
    app: &AppHandle,
) -> Result<
    (
        phantom_protocol::NatProfile,
        Vec<IceCandidate>,
        Arc<UdpSocket>,
        punch::Session,
    ),
    String,
> {
    let _ = app.emit("punch:phase", puncher::PunchPhase::Probing);
    if is_dev {
        let _ = app.emit("dev:log", "[打洞] 开始探测 NAT 画像...");
    }

    let stun = stun_servers_from(client).await;
    let rtt = client.signal_rtt_ms();

    let identity = client.identity();
    let (session, profile, candidates) = tokio::task::spawn_blocking(move || {
        let mut session = punch::Session::new();
        let (profile, candidates) = session.probe(&stun, rtt, &identity)?;
        Ok::<_, String>((session, profile, candidates))
    })
    .await
    .map_err(|e| format!("NAT 探测任务失败: {}", e))??;

    let sock = session
        .primary_socket()
        .ok_or_else(|| "打洞 socket 未就绪".to_string())?;

    if is_dev {
        let _ = app.emit(
            "dev:log",
            format!(
                "[打洞] NAT={:?} 基础候选 {} 个",
                profile.class,
                candidates.len()
            ),
        );
    }
    Ok((profile, candidates, sock, session))
}

/// 获取隧道统计数据
#[tauri::command]
async fn get_tunnel_stats(
    state: tauri::State<'_, StatsState>,
) -> Result<stats::StatsResponse, String> {
    Ok(state.manager.get_stats().await)
}

/// 重置隧道统计
#[tauri::command]
async fn reset_tunnel_stats(state: tauri::State<'_, StatsState>) -> Result<(), String> {
    state.manager.clear().await;
    Ok(())
}

fn should_start_host_relay(
    active_token: Option<&str>,
    requested_token: &str,
    connection_present: bool,
    connection_alive: bool,
) -> bool {
    let same_token = active_token == Some(requested_token);
    !(same_token && (connection_alive || !connection_present))
}

/// 启动中继隧道（打洞失败后调用）
#[tauri::command]
async fn start_relay_tunnel(
    app: AppHandle,
    relay_addr: String,
    relay_quic_port: u16,
    token: String,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
    signal_state: tauri::State<'_, SignalState>,
) -> Result<(), String> {
    abort_punch_task(&punch_state).await;
    let is_host = *punch_state.is_host.read().await;

    // 添加连接到统计系统
    let user_id = stats_state
        .manager
        .first_connection_id()
        .await
        .unwrap_or_else(|| "peer".to_string());
    stats_state
        .manager
        .add_connection(user_id.clone(), "relay".to_string())
        .await;
    stats_state
        .manager
        .set_connection_mode(&user_id, "relay")
        .await;
    // 顺便把最终连接模式上报给信令服务器，供管理面板展示
    let _ = signal_state
        .client
        .send(ClientMessage::ReportConnectionMode {
            mode: "relay".to_string(),
        })
        .await;
    tracing::info!("[统计] 已添加 Relay 连接");

    let relay_addr_resolved = resolve_relay_socket_addr(&relay_addr, relay_quic_port).await?;

    if is_host {
        let should_start = {
            let mut active_token = punch_state.relay_host_token.lock().await;
            let mut active_conn = punch_state.relay_host_conn.lock().await;
            let connection_alive = active_conn
                .as_ref()
                .map(|conn| conn.close_reason().is_none())
                .unwrap_or(false);
            let start = should_start_host_relay(
                active_token.as_deref(),
                &token,
                active_conn.is_some(),
                connection_alive,
            );

            if start {
                if let Some(old_conn) = active_conn.take() {
                    old_conn.close(0u32.into(), b"relay token changed");
                }
                *active_token = Some(token.clone());
                true
            } else {
                false
            }
        };

        if !should_start {
            tracing::info!(
                "[Relay] Host relay already active or connecting; reusing token {}",
                token
            );
            let _ = app.emit("tunnel:started", "Relay");
            return Ok(());
        }

        tracing::info!("[中继] Host 启动 QUIC 中继连接");
        let token_host = token.clone();
        let stats_for_host = stats_state.manager.clone();
        let user_for_host = user_id.clone();
        let app_clone = app.clone();
        tokio::spawn(async move {
            let ps = app_clone.state::<PunchState>();
            let tun = ps.tun_bridge.lock().await.clone();
            let crypto = ps.peer_crypto.lock().await.clone();
            match tunnel::connect_relay_quic_host(
                relay_addr_resolved,
                token_host.clone(),
                stats_for_host,
                user_for_host,
                tun,
                crypto,
            )
            .await
            {
                Ok(conn) => {
                    let state = app_clone.state::<PunchState>();
                    let token_is_current =
                        state.relay_host_token.lock().await.as_deref() == Some(token_host.as_str());
                    if token_is_current {
                        *state.relay_host_conn.lock().await = Some(conn);
                        let _ = app_clone.emit("tunnel:started", "Relay");
                    } else {
                        conn.close(0u32.into(), b"stale relay connection");
                    }
                }
                Err(e) => {
                    let state = app_clone.state::<PunchState>();
                    let mut active_token = state.relay_host_token.lock().await;
                    if active_token.as_deref() == Some(token_host.as_str()) {
                        *active_token = None;
                        if let Some(conn) = state.relay_host_conn.lock().await.take() {
                            conn.close(0u32.into(), b"relay connection failed");
                        }
                    }
                    tracing::error!("[中继] Host 连接失败: {}", e);
                    let _ = app_clone.emit(
                        "tunnel:failed",
                        TunnelFailedPayload {
                            mode: "Relay".to_string(),
                            reason: e,
                        },
                    );
                }
            }
        });
    } else {
        tracing::info!("[中继] Guest 启动 QUIC 中继连接");
        let token_guest = token.clone();
        let app_clone = app.clone();
        let stats_for_guest = stats_state.manager.clone();
        let user_for_guest = user_id.clone();
        tokio::spawn(async move {
            match tunnel::connect_relay_quic_guest(
                relay_addr_resolved,
                token_guest,
                stats_for_guest,
                user_for_guest,
            )
            .await
            {
                Ok(conn) => {
                    tracing::info!("[中继] Guest 透明 TUN 传输已连接");
                    let mgr = tunnel::TunnelConnManager::new(conn);
                    *app_clone.state::<PunchState>().conn_manager.lock().await = Some(mgr);
                    let _ = app_clone.emit("tunnel:started", "Relay");
                }
                Err(e) => {
                    tracing::error!("[中继] Guest 连接失败: {}", e);
                    let _ = app_clone.emit(
                        "tunnel:failed",
                        TunnelFailedPayload {
                            mode: "Relay".to_string(),
                            reason: e,
                        },
                    );
                }
            }
        });
    }

    Ok(())
}

async fn resolve_relay_socket_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    if port == 0 {
        return Err("中继端口为 0，无法建立连接".to_string());
    }
    let host = host.trim();
    if host.is_empty() {
        return Err("中继地址为空".to_string());
    }

    // 先尝试按 IP:port 直接解析
    if let Ok(addr) = format!("{}:{}", host, port).parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }

    // 再走 DNS 解析，优先 IPv4
    let target = format!("{}:{}", host, port);
    let addrs = tokio::net::lookup_host(target.clone())
        .await
        .map_err(|e| format!("DNS 解析中继地址失败 ({}): {}", target, e))?;

    let mut first = None;
    for addr in addrs {
        if first.is_none() {
            first = Some(addr);
        }
        if addr.is_ipv4() {
            return Ok(addr);
        }
    }

    first.ok_or_else(|| format!("DNS 未返回可用地址: {}", target))
}

/// 请求中继（强制中继模式）
#[tauri::command]
async fn request_relay(
    signal_state: tauri::State<'_, SignalState>,
    punch_state: tauri::State<'_, PunchState>,
) -> Result<(), String> {
    abort_punch_task(&punch_state).await;
    signal_state.client.send(ClientMessage::RelayRequest).await
}

/// 启动 TUN 虚拟网卡桥接
///
/// 在 QUIC 隧道建立后调用，使用已建立的 QUIC 连接
/// 创建虚拟网卡并开始透明转发。
#[tauri::command]
async fn start_tun_bridge(
    app: AppHandle,
    punch_state: tauri::State<'_, PunchState>,
    stats_state: tauri::State<'_, StatsState>,
) -> Result<(), String> {
    // 防止重复启动
    if punch_state
        .tun_enabled
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Ok(());
    }

    let subnet = punch_state.subnet.read().await.clone();
    if subnet.is_empty() {
        return Err("子网信息未就绪，无法启动 TUN".to_string());
    }

    let is_host = *punch_state.is_host.read().await;

    if is_host {
        return if punch_state.tun_bridge.lock().await.is_some() {
            Ok(())
        } else {
            Err("Host TUN 未在房间创建阶段成功启动".to_string())
        };
    }

    // 从连接管理器获取 QUIC 连接
    let conn = {
        let mgr = punch_state.conn_manager.lock().await;
        match mgr.as_ref() {
            Some(mgr) => mgr.get_conn().await,
            None => return Err("QUIC 连接未就绪".to_string()),
        }
    };

    let Some(quic_conn) = conn else {
        return Err("QUIC 连接已关闭".to_string());
    };

    // 启动 TUN 桥接
    let virtual_ip = punch_state.virtual_ip.read().await.clone();
    let host_virtual_ip = punch_state.host_virtual_ip.read().await.clone();
    // 没有会话密钥就不建隧道——绝不退回明文传输
    let crypto = punch_state
        .peer_crypto
        .lock()
        .await
        .clone()
        .ok_or("overlay 会话密钥尚未协商完成")?;
    // Guest 只有一条对端连接，取它作为流量与丢包统计的归属。
    // 没有它的话 tun_bridge 无处上报，带宽会一直显示 0。
    let peer_stats = stats_state
        .manager
        .first_connection_id()
        .await
        .map(|user| (stats_state.manager.clone(), user));
    let bridge = tun_bridge::TunBridge::start(
        &subnet,
        &virtual_ip,
        &host_virtual_ip,
        quic_conn,
        crypto,
        peer_stats,
    )
    .await
    .map_err(|e| format!("启动 TUN 桥接失败: {}", e))?;

    *punch_state.tun_bridge.lock().await = Some(bridge);
    punch_state
        .tun_enabled
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let host_ip = host_virtual_ip;
    let my_ip = virtual_ip;
    tracing::info!("[TUN] 虚拟网卡已启动: my={}, host={}", my_ip, host_ip);
    let _ = app.emit(
        "tun:ready",
        serde_json::json!({
            "my_ip": my_ip,
            "host_ip": host_ip,
            "subnet": subnet,
        }),
    );

    Ok(())
}

#[tauri::command]
fn show_main_window(window: tauri::WebviewWindow) {
    let _ = window.show();
}

/// 监控 TunnelConnManager 活跃流，在游戏断开连接（active=0持续3s）时触发静默中继升级
async fn watch_for_silent_upgrade(mgr: Arc<tunnel::TunnelConnManager>, app: AppHandle) {
    use std::time::{Duration, Instant};

    let mut idle_since: Option<Instant> = None;
    let required_idle = Duration::from_secs(3);
    let mut upgraded = false;

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        if upgraded {
            break;
        }

        let active = mgr.active_count();
        if active == 0 {
            if idle_since.is_none() {
                idle_since = Some(Instant::now());
            }
            if idle_since
                .map(|t| t.elapsed() >= required_idle)
                .unwrap_or(false)
            {
                // 触发静默升级
                let punch_state = app.state::<PunchState>();
                let prealloc_opt = punch_state.relay_prealloc.lock().await.clone();
                if let Some(prealloc) = prealloc_opt {
                    let relay_sa_str = format!("{}:{}", prealloc.relay_addr, 0);
                    if let Ok(relay_sa) = relay_sa_str.parse::<std::net::SocketAddr>() {
                        tracing::info!("[静默升级] active_streams=0 超过3s，开始连接中继...");
                        match tunnel::preconnect_relay_quic_guest(relay_sa, prealloc.token).await {
                            Ok(new_conn) => {
                                mgr.upgrade(new_conn).await;
                                let _ = app.emit("tunnel:upgraded", "relay");
                                tracing::info!("[静默升级] 完成，隧道已切换到中继");
                                upgraded = true;
                            }
                            Err(e) => {
                                tracing::warn!("[静默升级] 中继连接失败: {}，将在下次机会重试", e);
                                idle_since = None; // 重置，等待下次机会
                            }
                        }
                    }
                }
            }
        } else {
            idle_since = None;
        }
    }
}

/// 如果不是以管理员身份运行，则弹 UAC 提权重新启动
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
    enable_windows_dev_console(dev_mode);

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
    let log_dir = client_log_dir();
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

    // 初始化设备身份
    let data_dir = app_data_dir;

    // 风控自校准库：运营商的包速率阈值各地不同、用户无法预先测（《踩坑记录》
    // 第十一条），只能在每个用户自己的环境里学，并且跨会话留存。
    // 这里只是把库准备好；**链路干净的会话完全不会读它**，
    // 见 `phantom_core::repair::calibration` 的"零开销路径"。
    let calibration_store = Arc::new(phantom_core::repair::CalibrationStore::new(&data_dir));
    tracing::info!(
        "[启动] 风控自校准库: {}",
        calibration_store.path().display()
    );
    let identity = match identity::Identity::load_or_generate(&data_dir) {
        Ok(id) => Arc::new(id),
        Err(e) => {
            tracing::error!("[启动] 初始化身份失败: {}", e);
            panic!("无法初始化设备身份: {}", e);
        }
    };
    tracing::info!("[启动] 设备 ID: {}", identity.short_id());

    let signal_client = Arc::new(signal::client::SignalClient::new(identity, dev_mode));

    // 初始化统计管理器（默认为 Guest，创建房间时会更新为 Host）
    let stats_manager = Arc::new(stats::StatsManager::new(false));

    tauri::Builder::default()
        .manage(SignalState {
            client: signal_client,
        })
        .manage(PunchState {
            socket: tokio::sync::Mutex::new(None),
            punch_task: tokio::sync::Mutex::new(None),
            is_host: tokio::sync::RwLock::new(false),
            local_ice_candidates: tokio::sync::Mutex::new(Vec::new()),
            punch_sessions: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            peer_crypto: tokio::sync::Mutex::new(None),
            relay_prealloc: tokio::sync::Mutex::new(None),
            conn_manager: tokio::sync::Mutex::new(None),
            ice_task: tokio::sync::Mutex::new(None),
            host_ice_tasks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            host_endpoint: tokio::sync::Mutex::new(None),
            host_peers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            relay_host_token: tokio::sync::Mutex::new(None),
            relay_host_conn: tokio::sync::Mutex::new(None),
            tun_bridge: tokio::sync::Mutex::new(None),
            subnet: tokio::sync::RwLock::new(String::new()),
            virtual_ip: tokio::sync::RwLock::new(String::new()),
            host_virtual_ip: tokio::sync::RwLock::new(String::new()),
            tun_enabled: AtomicBool::new(false),
        })
        .manage(StatsState {
            manager: stats_manager.clone(),
        })
        .manage(CalibrationState {
            store: calibration_store,
        })
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
            // 在 Tauri 的异步运行时中启动采样任务
            tauri::async_runtime::spawn(async move {
                stats_manager.start_sampling_task();
            });

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
            get_network_info,
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

#[cfg(test)]
mod tests {
    use super::should_start_host_relay;

    #[test]
    fn host_relay_is_idempotent_per_room_token() {
        assert!(should_start_host_relay(None, "room-a", false, false));
        assert!(!should_start_host_relay(
            Some("room-a"),
            "room-a",
            false,
            false
        ));
        assert!(!should_start_host_relay(
            Some("room-a"),
            "room-a",
            true,
            true
        ));
        assert!(should_start_host_relay(
            Some("room-a"),
            "room-a",
            true,
            false
        ));
        assert!(should_start_host_relay(
            Some("room-a"),
            "room-b",
            true,
            true
        ));
    }
}
