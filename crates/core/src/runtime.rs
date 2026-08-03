//! 平台无关的会话运行时。
//!
//! 连接的完整编排——信令 → NAT 探测 → 三阶段打洞 → 建隧道 → 中继回退——
//! 在三个客户端之间是同一件事，因此实现只留这一份：桌面端（`src-tauri`）、
//! headless 端（`src-web`）与 Android（`crates/mobile` 的 JNI 桥）都调用它。
//!
//! 各宿主之间真正的差异只有三点，由 [`RuntimeHost`] 注入：事件如何投递给界面、
//! 日志写到哪里、数据目录在哪里。Android 的日志必须落在应用外部目录
//! （`getExternalFilesDir`）才能在未 root 的设备上取到，这正是日志根目录
//! 不能在 core 里写死的原因。

use crate::{
    config::ClientConfig, identity::Identity, network, punch, puncher, signal, stats, tun_bridge,
    tunnel,
};
use phantom_protocol::{
    ClientMessage, IceCandidate, NatProfile, PunchParams, PunchStrategy, ServerMessage,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, Mutex, RwLock};

/// 宿主平台需要提供给运行时的能力。
///
/// 实现要点：[`emit`](RuntimeHost::emit) 会在信令消息循环里被同步调用，
/// 实现必须立即返回，不能阻塞——耗时的投递自行转异步。
pub trait RuntimeHost: Send + Sync + 'static {
    /// 把事件投递给界面。桌面端走 Tauri 的 `emit`，headless 端走 broadcast
    /// 通道再转 SSE，Android 走 JNI 回调。
    fn emit(&self, event: &str, data: Value);

    /// 日志根目录。桌面端在配置目录下的 `log/`；Android 必须是
    /// `getExternalFilesDir()`，否则无 root 的设备根本读不到日志。
    fn log_dir(&self) -> PathBuf;

    /// 身份密钥与配置的存放目录。
    fn data_dir(&self) -> PathBuf {
        ClientConfig::config_path()
            .parent()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// 桌面端与 headless 端共用的日志目录：配置目录下的 `log/`。
/// Android 不适用，见 [`RuntimeHost::log_dir`]。
pub fn default_log_directory() -> PathBuf {
    ClientConfig::config_path()
        .parent()
        .map(|d| d.join("log"))
        .unwrap_or_else(|| PathBuf::from("log"))
}

#[derive(Clone, Debug, Serialize)]
pub struct UiEvent {
    pub event: String,
    pub data: Value,
}

#[derive(Clone)]
struct RelayInfo {
    relay_addr: String,
    relay_quic_port: u16,
    token: String,
}

struct HostPeer {
    socket: Arc<UdpSocket>,
    endpoint: Option<quinn::Endpoint>,
}

/// 每个对端一套打洞会话（三阶段状态机在 phantom-core 里，两个客户端共用）
type PunchSessions = HashMap<String, punch::Session>;

struct RuntimeState {
    authenticated_user: Option<String>,
    fixed_host_ip: Option<String>,
    room_code: Option<String>,
    is_host: bool,
    subnet: String,
    virtual_ip: String,
    host_virtual_ip: String,
    socket: Option<Arc<UdpSocket>>,
    local_candidates: Vec<IceCandidate>,
    /// 打洞会话：Guest 端只有一个（键为 Host 的 session_id），
    /// Host 端每个 Guest 一个
    punch_sessions: PunchSessions,
    /// 打洞阶段协商出的 overlay 会话密钥。
    /// P2P 与中继两条路径共用同一份——中继只做盲转发，看不到明文。
    peer_crypto: Option<Arc<crate::crypto::SessionCrypto>>,
    relay: Option<RelayInfo>,
    conn_manager: Option<Arc<tunnel::TunnelConnManager>>,
    host_endpoint: Option<quinn::Endpoint>,
    host_peers: HashMap<String, HostPeer>,
    host_ice_tasks: HashMap<String, tokio::task::JoinHandle<()>>,
    /// 房间里所有 Guest 共用 Host 这一条中继连接，因此要记住它对应的
    /// token：token 没变且连接还活着时**不能重连**，否则会把正在通过它
    /// 转发的其他 Guest 一起掐断。判定见 [`should_start_host_relay`]。
    relay_host_token: Option<String>,
    relay_host_conn: Option<quinn::Connection>,
    tun_bridge: Option<Arc<tun_bridge::TunBridge>>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            authenticated_user: None,
            fixed_host_ip: None,
            room_code: None,
            is_host: false,
            subnet: String::new(),
            virtual_ip: String::new(),
            host_virtual_ip: String::new(),
            socket: None,
            local_candidates: Vec::new(),
            punch_sessions: HashMap::new(),
            peer_crypto: None,
            relay: None,
            conn_manager: None,
            host_endpoint: None,
            host_peers: HashMap::new(),
            host_ice_tasks: HashMap::new(),
            relay_host_token: None,
            relay_host_conn: None,
            tun_bridge: None,
        }
    }
}

pub struct SessionRuntime {
    signal: Arc<signal::client::SignalClient>,
    stats: Arc<stats::StatsManager>,
    state: Mutex<RuntimeState>,
    config: RwLock<ClientConfig>,
    host: Arc<dyn RuntimeHost>,
    overlay_ip: watch::Sender<Option<Ipv4Addr>>,
    auto_host: AtomicBool,
}

impl SessionRuntime {
    pub fn new(host: Arc<dyn RuntimeHost>) -> Result<Arc<Self>, String> {
        crate::ensure_rustls_crypto_provider()?;
        let config = ClientConfig::load();
        let identity = Arc::new(Identity::load_or_generate(&host.data_dir())?);
        let signal = Arc::new(signal::client::SignalClient::new(identity, config.dev_mode));
        let stats = Arc::new(stats::StatsManager::new(false));
        stats.clone().start_sampling_task();
        let (overlay_ip, _) = watch::channel(None);
        Ok(Arc::new(Self {
            signal,
            stats,
            state: Mutex::new(RuntimeState::default()),
            config: RwLock::new(config),
            host,
            overlay_ip,
            auto_host: AtomicBool::new(false),
        }))
    }

    pub fn overlay_receiver(&self) -> watch::Receiver<Option<Ipv4Addr>> {
        self.overlay_ip.subscribe()
    }

    pub async fn start(self: &Arc<Self>, signal_url: String, auto_host: bool) {
        self.auto_host.store(auto_host, Ordering::Relaxed);
        self.signal.connect(signal_url).await;
        if let Some(mut receiver) = self.signal.take_event_rx().await {
            let runtime = self.clone();
            tokio::spawn(async move {
                while let Some(message) = receiver.recv().await {
                    runtime.handle_server_message(message).await;
                }
            });
        }
    }

    fn emit<T: Serialize>(&self, event: &str, payload: T) {
        if let Ok(data) = serde_json::to_value(payload) {
            self.host.emit(event, data);
        }
    }

    async fn emit_status(&self) {
        self.emit(
            "signal:status",
            json!({
                "state": self.signal.get_state().await.to_string(),
                "session_id": self.signal.get_session_id().await,
                "room_code": self.signal.get_room_code().await,
            }),
        );
    }

    pub async fn snapshot(&self) -> Vec<UiEvent> {
        let state = self.state.lock().await;
        let mut events = vec![UiEvent {
            event: "signal:status".into(),
            data: json!({
                "state": self.signal.get_state().await.to_string(),
                "session_id": self.signal.get_session_id().await,
                "room_code": state.room_code,
            }),
        }];
        if let Some(user_id) = &state.authenticated_user {
            events.push(UiEvent {
                event: "signal:auth_ok".into(),
                data: json!({"user_id": user_id}),
            });
            events.push(UiEvent {
                event: "signal:fixed_host_ip_status".into(),
                data: json!({"enabled": state.fixed_host_ip.is_some(), "virtual_ip": state.fixed_host_ip}),
            });
        }
        if state.is_host {
            if let Some(room_code) = &state.room_code {
                events.push(UiEvent {
                    event: "signal:room_created".into(),
                    data: json!({
                        "room_code": room_code,
                        "subnet": state.subnet,
                        "virtual_ip": state.virtual_ip,
                    }),
                });
                if state.tun_bridge.is_some() {
                    events.push(UiEvent {
                        event: "tun:ready".into(),
                        data: json!({"my_ip": state.virtual_ip, "host_ip": state.virtual_ip, "subnet": state.subnet}),
                    });
                }
            }
        }
        events
    }

    async fn handle_server_message(self: &Arc<Self>, message: ServerMessage) {
        let event_name = server_event_name(&message);
        self.emit(event_name, &message);

        match message {
            ServerMessage::AuthOk { user_id } => {
                self.state.lock().await.authenticated_user = Some(user_id);
                if self.auto_host.load(Ordering::Relaxed)
                    && self.signal.get_room_code().await.is_none()
                {
                    if let Err(error) = self.create_room().await {
                        self.emit("signal:error", json!({"message": error}));
                    }
                }
            }
            ServerMessage::FixedHostIpStatus { virtual_ip, .. } => {
                self.state.lock().await.fixed_host_ip = virtual_ip;
            }
            ServerMessage::RoomCreated {
                room_code,
                subnet,
                virtual_ip,
            } => {
                if let Some(old) = self.state.lock().await.tun_bridge.take() {
                    old.close().await;
                }
                if let Some(old) = self.state.lock().await.conn_manager.take() {
                    old.close().await;
                }
                if let Some(old) = self.state.lock().await.host_endpoint.take() {
                    old.close(0u32.into(), b"Host address changed");
                }
                for (_, peer) in std::mem::take(&mut self.state.lock().await.host_peers) {
                    if let Some(endpoint) = peer.endpoint {
                        endpoint.close(0u32.into(), b"Host address changed");
                    }
                }
                for (_, task) in std::mem::take(&mut self.state.lock().await.host_ice_tasks) {
                    task.abort();
                }
                if let Some(old) = self.state.lock().await.relay_host_conn.take() {
                    old.close(0u32.into(), b"Host address changed");
                }
                {
                    let mut state = self.state.lock().await;
                    state.room_code = Some(room_code.clone());
                    state.is_host = true;
                    state.subnet = subnet.clone();
                    state.virtual_ip = virtual_ip.clone();
                    state.host_virtual_ip = virtual_ip.clone();
                }
                match tun_bridge::TunBridge::start_host(&subnet, &virtual_ip).await {
                    Ok(bridge) => {
                        self.state.lock().await.tun_bridge = Some(bridge);
                        if let Ok(ip) = virtual_ip.parse() {
                            let _ = self.overlay_ip.send(Some(ip));
                        }
                        self.emit(
                            "tun:ready",
                            json!({"my_ip": virtual_ip, "host_ip": virtual_ip, "subnet": subnet}),
                        );
                        let _ = self.signal.send(ClientMessage::HostReady).await;
                        // 房主信息如何呈现由宿主决定：headless 端打印到终端，
                        // 桌面端与 Android 走各自的界面。core 只负责把事实发出去。
                        self.emit(
                            "room:host_ready",
                            json!({
                                "room_code": room_code,
                                "virtual_ip": virtual_ip,
                                "subnet": subnet,
                            }),
                        );
                    }
                    Err(error) => {
                        tracing::error!("[TUN] Host device initialization failed: {}", error);
                        self.emit("tun:failed", error.to_string());
                        let _ = self.signal.send(ClientMessage::CloseRoom).await;
                    }
                }
            }
            ServerMessage::JoinOk {
                room_code,
                subnet,
                virtual_ip,
                host_virtual_ip,
                ..
            } => {
                {
                    let mut state = self.state.lock().await;
                    state.room_code = Some(room_code);
                    state.is_host = false;
                    state.subnet = subnet;
                    state.virtual_ip = virtual_ip;
                    state.host_virtual_ip = host_virtual_ip;
                }
                if let Err(error) = self.start_punch().await {
                    self.emit("punch:phase", puncher::PunchPhase::Failed { reason: error });
                }
            }
            ServerMessage::PeerJoined {
                peer_session_id, ..
            } => {
                self.stats
                    .add_connection(peer_session_id.clone(), "p2p".into())
                    .await;
                let result = if self.state.lock().await.is_host {
                    self.start_host_punch_for_peer(&peer_session_id).await
                } else {
                    self.start_punch().await
                };
                if let Err(error) = result {
                    self.emit("punch:phase", puncher::PunchPhase::Failed { reason: error });
                }
            }
            ServerMessage::PeerLeft {
                peer_session_id, ..
            } => {
                self.stats.remove_connection(&peer_session_id).await;
                if let Some(task) = self
                    .state
                    .lock()
                    .await
                    .host_ice_tasks
                    .remove(&peer_session_id)
                {
                    task.abort();
                }
                if let Some(peer) = self.state.lock().await.host_peers.remove(&peer_session_id) {
                    if let Some(endpoint) = peer.endpoint {
                        endpoint.close(0u32.into(), b"peer left");
                    }
                }
            }
            ServerMessage::RelayPreAllocated {
                relay_addr,
                relay_quic_port,
                token,
                ..
            } => {
                self.state.lock().await.relay = Some(RelayInfo {
                    relay_addr,
                    relay_quic_port,
                    token,
                });
            }
            ServerMessage::RelayReady {
                relay_addr,
                relay_quic_port,
                token,
                ..
            } => {
                let relay = RelayInfo {
                    relay_addr,
                    relay_quic_port,
                    token,
                };
                self.state.lock().await.relay = Some(relay.clone());
                if let Err(error) = self.start_relay(relay).await {
                    self.emit("tunnel:failed", json!({"mode": "Relay", "reason": error}));
                }
            }
            ServerMessage::PunchPlan {
                peer_session_id,
                attempt_id,
                strategy,
                params,
                peer_profile,
                ..
            } => {
                self.handle_punch_plan(peer_session_id, attempt_id, strategy, params, peer_profile)
                    .await;
            }
            ServerMessage::PunchStart {
                peer_session_id,
                peer_candidates,
                start_delay_ms,
                ..
            } => {
                let runtime = self.clone();
                let peer_id = peer_session_id.clone();
                let task = tokio::spawn(async move {
                    runtime
                        .handle_punch_start(peer_session_id, peer_candidates, start_delay_ms)
                        .await;
                });
                if self.state.lock().await.is_host {
                    self.state.lock().await.host_ice_tasks.insert(peer_id, task);
                }
            }
            ServerMessage::RequestLogUpload { upload_url, reason } => {
                self.upload_logs(upload_url, reason).await;
            }
            ServerMessage::RoomClosed { .. } => self.reset_room().await,
            _ => {}
        }
        self.emit_status().await;
    }

    /// 收到上传凭据后打包并上传日志。
    ///
    /// 打包与 HTTP 传输都是阻塞操作，放到 blocking 线程池，
    /// 避免拖住信令消息循环。
    async fn upload_logs(&self, upload_url: String, reason: String) {
        let dir = self.host.log_dir();
        let result = tokio::task::spawn_blocking(move || {
            let uploader = crate::log_upload::LogUploader::new(&dir);
            // 先补投历史失败的包——它们往往正是"网络有问题"那次的日志
            uploader.flush_pending();
            uploader.upload_now(&upload_url, &reason)
        })
        .await;

        match result {
            Ok(Ok(bytes)) => {
                self.emit("log:uploaded", json!({"bytes": bytes}));
            }
            Ok(Err(e)) => {
                tracing::warn!("[日志上报] {}", e);
                self.emit("log:upload_failed", json!({"reason": e}));
            }
            Err(e) => tracing::warn!("[日志上报] 任务失败: {}", e),
        }
    }

    /// 主动请求上传日志（用户点击"反馈问题"）
    pub async fn request_log_upload(&self, reason: String) -> Result<(), String> {
        self.signal
            .send(ClientMessage::RequestLogUpload { reason })
            .await
    }

    /// 取服务端下发的 STUN 列表（自建优先）。
    /// 客户端不内置任何地址——公共 STUN 不可用时会直接导致拿不到 srflx 候选而落中继。
    async fn stun_servers(&self) -> Vec<(String, u16)> {
        // 必须等配置到位再探测：拿空列表跑完只会得到 class=Unknown、
        // 没有 srflx 候选，打洞从一开始就注定失败
        match self
            .signal
            .wait_for_network_config(std::time::Duration::from_secs(5))
            .await
        {
            Some(cfg) => cfg
                .stun_servers
                .iter()
                .map(|s| (s.host.clone(), s.port))
                .collect(),
            None => {
                tracing::warn!("[打洞] 服务端未下发 STUN 配置，无法获得公网映射");
                Vec::new()
            }
        }
    }

    /// **阶段一**：探测 NAT 画像并上报（Guest 侧，或 Host 面向单个 Guest）。
    async fn begin_punch(&self, target_peer: Option<String>) -> Result<(), String> {
        let stun = self.stun_servers().await;
        let rtt = self.signal.signal_rtt_ms();
        // 会话键：Guest 用 None（对端就是 Host），Host 用具体的 Guest id
        let key = target_peer
            .clone()
            .unwrap_or_else(|| "__host__".to_string());

        self.emit("punch:phase", puncher::PunchPhase::Probing);

        let identity = self.signal.identity();
        let (mut session, profile, candidates) = tokio::task::spawn_blocking(move || {
            let mut session = punch::Session::new();
            let (profile, candidates) = session.probe(&stun, rtt, &identity)?;
            Ok::<_, String>((session, profile, candidates))
        })
        .await
        .map_err(|e| e.to_string())??;

        let socket = session
            .primary_socket()
            .ok_or_else(|| "打洞 socket 未就绪".to_string())?;

        {
            let mut state = self.state.lock().await;
            if let Some(peer) = &target_peer {
                state.host_peers.insert(
                    peer.clone(),
                    HostPeer {
                        socket: socket.clone(),
                        endpoint: None,
                    },
                );
            } else {
                state.socket = Some(socket);
                state.local_candidates = candidates.clone();
            }
            state
                .punch_sessions
                .insert(key, std::mem::take(&mut session));
        }

        self.signal
            .send(ClientMessage::NatProfileReport {
                target_peer_session_id: target_peer,
                profile,
                base_candidates: candidates,
            })
            .await?;
        self.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
        Ok(())
    }

    async fn start_punch(&self) -> Result<(), String> {
        // Host 的 socket 是长期存活的，已有候选就直接复用重报，
        // 不要重新探测——否则会毁掉已经建立的连接
        let existing = {
            let state = self.state.lock().await;
            if state.is_host && !state.local_candidates.is_empty() {
                Some(state.local_candidates.clone())
            } else {
                None
            }
        };
        if existing.is_some() {
            self.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
            return Ok(());
        }
        self.begin_punch(None).await
    }

    async fn start_host_punch_for_peer(&self, peer_session_id: &str) -> Result<(), String> {
        if self
            .state
            .lock()
            .await
            .host_peers
            .contains_key(peer_session_id)
        {
            return Ok(());
        }
        self.begin_punch(Some(peer_session_id.to_string())).await
    }

    /// **阶段二**：收到服务端下发的策略计划。
    ///
    /// 需要新建 socket 的策略（对称 NAT 侧）在这里创建并探测它们的映射，
    /// 回报给对端；快速通道策略无需二次交换，此处不会产生候选。
    async fn handle_punch_plan(
        &self,
        peer_session_id: String,
        attempt_id: String,
        strategy: PunchStrategy,
        params: PunchParams,
        peer_profile: NatProfile,
    ) {
        let key = self.session_key(&peer_session_id).await;
        let stun = self.stun_servers().await;

        let extra = {
            let mut state = self.state.lock().await;
            // Host 恒为 initiator：双方必须得出相反的角色，
            // 否则会各自用同一把密钥发送，导致 nonce 复用
            let is_initiator = state.is_host;
            let Some(session) = state.punch_sessions.get_mut(&key) else {
                tracing::warn!("[打洞] 收到计划但会话不存在: {}", key);
                return;
            };
            session.on_plan(
                attempt_id.clone(),
                strategy,
                params,
                peer_profile,
                &stun,
                is_initiator,
            )
        };

        if !extra.is_empty() {
            if let Err(e) = self
                .signal
                .send(ClientMessage::StrategyCandidates {
                    target_peer_session_id: peer_session_id,
                    attempt_id,
                    candidates: extra,
                })
                .await
            {
                tracing::warn!("[打洞] 上报策略候选失败: {}", e);
            }
        }
    }

    /// Guest 侧只有一个会话；Host 侧按 Guest 的 session_id 分别持有
    async fn session_key(&self, peer_session_id: &str) -> String {
        if self.state.lock().await.is_host {
            peer_session_id.to_string()
        } else {
            "__host__".to_string()
        }
    }

    /// **阶段三**：按计划执行打洞，无论成败都上报结构化遥测。
    async fn handle_punch_start(
        self: Arc<Self>,
        peer_session_id: String,
        peer_candidates: Vec<IceCandidate>,
        start_delay_ms: u32,
    ) {
        let key = self.session_key(&peer_session_id).await;
        let (is_host, room_code) = {
            let state = self.state.lock().await;
            (state.is_host, state.room_code.clone().unwrap_or_default())
        };
        let ctx = punch::RecordContext::new(room_code, peer_session_id.clone(), is_host);

        let mut session = {
            let mut state = self.state.lock().await;
            match state.punch_sessions.remove(&key) {
                Some(s) => s,
                None => {
                    self.emit(
                        "punch:phase",
                        puncher::PunchPhase::Failed {
                            reason: "打洞会话未就绪".into(),
                        },
                    );
                    return;
                }
            }
        };

        self.emit("punch:phase", puncher::PunchPhase::Punching);
        let outcome = session.run(peer_candidates, start_delay_ms, ctx).await;

        // 成败都上报——失败样本对分析 NAT 组合成功率同样重要
        if let Err(e) = self
            .signal
            .send(ClientMessage::PunchReport {
                record: outcome.record.clone(),
            })
            .await
        {
            tracing::warn!("[打洞] 遥测上报失败: {}", e);
        }

        let Some(success) = outcome.success else {
            if is_host {
                if let Some(peer) = self.state.lock().await.host_peers.remove(&peer_session_id) {
                    if let Some(endpoint) = peer.endpoint {
                        endpoint.close(0u32.into(), b"punch failed");
                    }
                }
            }
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: format!("{:?}", outcome.record.outcome),
                },
            );
            if let Some(relay) = self.state.lock().await.relay.clone() {
                if let Err(error) = self.start_relay(relay).await {
                    self.emit("tunnel:failed", json!({"mode": "Relay", "reason": error}));
                }
            }
            return;
        };

        // 打通的正是这个 socket 的映射，隧道必须复用它，换 socket 等于白打
        let Some(socket) = outcome.socket else {
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: "命中的 socket 丢失".into(),
                },
            );
            return;
        };
        {
            let mut state = self.state.lock().await;
            // 数据面必须用这把密钥；没有它就只能明文，宁可不建隧道
            state.peer_crypto = outcome.crypto.clone();
            if is_host {
                if let Some(peer) = state.host_peers.get_mut(&peer_session_id) {
                    peer.socket = socket.clone();
                }
            } else {
                state.socket = Some(socket.clone());
            }
        }
        if outcome.crypto.is_none() {
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: "overlay 会话密钥协商失败".into(),
                },
            );
            return;
        }

        let result = puncher::PunchResult {
            success: true,
            peer_addr: success.peer_addr.to_string(),
            latency_ms: success.rtt_ms,
            reason: String::new(),
        };

        self.emit(
            "punch:phase",
            puncher::PunchPhase::Success {
                latency_ms: result.latency_ms,
            },
        );
        self.stats
            .add_connection(peer_session_id.clone(), "p2p".into())
            .await;
        if is_host {
            let mut state = self.state.lock().await;
            match socket
                .try_clone()
                .map_err(|e| e.to_string())
                .and_then(tunnel::create_host_endpoint)
            {
                Ok(endpoint) => {
                    let task_endpoint = endpoint.clone();
                    let stats = self.stats.clone();
                    let tun = state.tun_bridge.clone();
                    let crypto = state.peer_crypto.clone();
                    let peer_map = Arc::new(Mutex::new(HashMap::from([(
                        result.peer_addr.clone(),
                        peer_session_id.clone(),
                    )])));
                    tokio::spawn(async move {
                        let _ =
                            tunnel::start_host_tunnel(task_endpoint, stats, peer_map, tun, crypto)
                                .await;
                    });
                    if let Some(peer) = state.host_peers.get_mut(&peer_session_id) {
                        peer.endpoint = Some(endpoint);
                    }
                }
                Err(error) => {
                    drop(state);
                    self.emit("tunnel:failed", json!({"mode": "P2P", "reason": error}));
                    return;
                }
            }
            drop(state);
            self.emit("tunnel:started", "P2P");
        } else {
            let peer: SocketAddr = match result.peer_addr.parse() {
                Ok(peer) => peer,
                Err(error) => {
                    self.emit(
                        "tunnel:failed",
                        json!({"mode": "P2P", "reason": error.to_string()}),
                    );
                    return;
                }
            };
            let connection = match socket.try_clone().map_err(|e| e.to_string()) {
                Ok(socket) => match tunnel::create_guest_connection(socket, peer).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        self.emit("tunnel:failed", json!({"mode": "P2P", "reason": error}));
                        return;
                    }
                },
                Err(error) => {
                    self.emit("tunnel:failed", json!({"mode": "P2P", "reason": error}));
                    return;
                }
            };
            let manager = tunnel::TunnelConnManager::new(connection);
            let _ = tunnel::start_guest_tunnel_managed(
                manager.clone(),
                0,
                0,
                self.stats.clone(),
                peer_session_id,
            )
            .await;
            self.state.lock().await.conn_manager = Some(manager);
            if let Err(error) = self.start_guest_tun().await {
                self.emit("tun:failed", error);
                return;
            }
            self.emit("tunnel:started", "P2P");
        }
    }

    async fn start_relay(&self, relay: RelayInfo) -> Result<(), String> {
        let address = resolve_ipv4(&relay.relay_addr, relay.relay_quic_port).await?;
        let (is_host, tun, crypto) = {
            let state = self.state.lock().await;
            (
                state.is_host,
                state.tun_bridge.clone(),
                state.peer_crypto.clone(),
            )
        };
        let user = self
            .stats
            .first_connection_id()
            .await
            .unwrap_or_else(|| "peer".into());
        self.stats
            .add_connection(user.clone(), "relay".into())
            .await;
        if is_host {
            // 同一个房间里每个 Guest 回落中继都会触发一次 RelayReady，
            // 但 Host 只应该有一条中继连接。token 未变且连接仍活着时直接复用，
            // 否则会把正在经由它转发的其他 Guest 一并掐断。
            let should_start = {
                let mut state = self.state.lock().await;
                let connection_alive = state
                    .relay_host_conn
                    .as_ref()
                    .map(|conn| conn.close_reason().is_none())
                    .unwrap_or(false);
                let start = should_start_host_relay(
                    state.relay_host_token.as_deref(),
                    &relay.token,
                    state.relay_host_conn.is_some(),
                    connection_alive,
                );
                if start {
                    if let Some(old) = state.relay_host_conn.take() {
                        old.close(0u32.into(), b"relay token changed");
                    }
                    state.relay_host_token = Some(relay.token.clone());
                }
                start
            };

            if !should_start {
                tracing::info!("[中继] Host 中继连接已就绪，复用 token {}", relay.token);
                self.emit("tunnel:started", "Relay");
                return Ok(());
            }

            let connection = tunnel::connect_relay_quic_host(
                address,
                relay.token,
                self.stats.clone(),
                user,
                tun,
                crypto,
            )
            .await?;
            self.state.lock().await.relay_host_conn = Some(connection);
        } else {
            let connection =
                tunnel::connect_relay_quic_guest(address, relay.token, self.stats.clone(), user)
                    .await?;
            let existing = self.state.lock().await.conn_manager.clone();
            if let Some(manager) = existing {
                // Keep the transparent TUN and active application streams;
                // TunnelConnManager switches new packets to the relay.
                manager.upgrade(connection).await;
            } else {
                self.state.lock().await.conn_manager =
                    Some(tunnel::TunnelConnManager::new(connection));
            }
            self.start_guest_tun().await?;
        }
        self.emit("tunnel:started", "Relay");
        Ok(())
    }

    async fn start_guest_tun(&self) -> Result<(), String> {
        let (subnet, virtual_ip, host_ip, connection, already_started, crypto) = {
            let state = self.state.lock().await;
            let connection = match &state.conn_manager {
                Some(manager) => manager.get_conn().await,
                None => None,
            };
            (
                state.subnet.clone(),
                state.virtual_ip.clone(),
                state.host_virtual_ip.clone(),
                connection,
                state.tun_bridge.is_some(),
                state.peer_crypto.clone(),
            )
        };
        if already_started {
            return Ok(());
        }
        let connection = connection.ok_or("QUIC connection is not ready")?;
        // 没有会话密钥就不建隧道——绝不退回明文传输
        let crypto = crypto.ok_or("overlay 会话密钥尚未协商完成")?;
        let bridge =
            tun_bridge::TunBridge::start(&subnet, &virtual_ip, &host_ip, connection, crypto)
                .await
                .map_err(|e| e.to_string())?;
        self.state.lock().await.tun_bridge = Some(bridge);
        self.emit(
            "tun:ready",
            json!({"my_ip": virtual_ip, "host_ip": host_ip, "subnet": subnet}),
        );
        Ok(())
    }

    async fn reset_room(&self) {
        let mut state = self.state.lock().await;
        if let Some(bridge) = state.tun_bridge.take() {
            bridge.close().await;
        }
        if let Some(manager) = state.conn_manager.take() {
            manager.close().await;
        }
        if let Some(endpoint) = state.host_endpoint.take() {
            endpoint.close(0u32.into(), b"room closed");
        }
        for (_, peer) in std::mem::take(&mut state.host_peers) {
            if let Some(endpoint) = peer.endpoint {
                endpoint.close(0u32.into(), b"room closed");
            }
        }
        for (_, task) in std::mem::take(&mut state.host_ice_tasks) {
            task.abort();
        }
        if let Some(connection) = state.relay_host_conn.take() {
            connection.close(0u32.into(), b"room closed");
        }
        let authenticated_user = state.authenticated_user.clone();
        let fixed_host_ip = state.fixed_host_ip.clone();
        *state = RuntimeState {
            authenticated_user,
            fixed_host_ip,
            ..RuntimeState::default()
        };
        let _ = self.overlay_ip.send(None);
        self.stats.clear().await;
    }

    async fn create_room(&self) -> Result<(), String> {
        self.reset_room().await;
        self.stats.set_host_mode(true);
        self.state.lock().await.is_host = true;
        self.signal.send(ClientMessage::CreateRoom).await
    }

    async fn join_room(&self, room_code: String) -> Result<(), String> {
        self.reset_room().await;
        self.stats.set_host_mode(false);
        self.signal
            .send(ClientMessage::JoinRoom { room_code })
            .await
    }

    pub async fn invoke(self: &Arc<Self>, command: &str, payload: Value) -> Result<Value, String> {
        match command {
            "is_dev_mode" => Ok(json!(false)),
            "show_main_window" => Ok(Value::Null),
            "connect_signal" => {
                if self.signal.get_state().await == signal::client::ConnectionState::Disconnected {
                    let requested = payload
                        .get("signalUrl")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let url = crate::config::runtime_signal_server(requested);
                    self.signal.connect(url).await;
                }
                // 重放当前状态，让刚接上的界面立刻看到完整快照
                for event in self.snapshot().await {
                    self.host.emit(&event.event, event.data);
                }
                Ok(Value::Null)
            }
            "disconnect_signal" => {
                self.reset_room().await;
                self.signal.disconnect().await;
                Ok(Value::Null)
            }
            "create_room" => {
                self.create_room().await?;
                Ok(Value::Null)
            }
            "join_room" => {
                let room = payload
                    .get("roomCode")
                    .and_then(Value::as_str)
                    .ok_or("roomCode is required")?;
                self.join_room(room.trim().to_uppercase()).await?;
                Ok(Value::Null)
            }
            "leave_room" => {
                self.signal.send(ClientMessage::LeaveRoom).await?;
                self.reset_room().await;
                Ok(Value::Null)
            }
            "close_room" => {
                self.signal.send(ClientMessage::CloseRoom).await?;
                self.reset_room().await;
                Ok(Value::Null)
            }
            "request_fixed_host_ip" => {
                self.signal.send(ClientMessage::RequestFixedHostIp).await?;
                Ok(Value::Null)
            }
            "release_fixed_host_ip" => {
                self.signal.send(ClientMessage::ReleaseFixedHostIp).await?;
                Ok(Value::Null)
            }
            "get_fixed_host_ip" => {
                self.signal.send(ClientMessage::GetFixedHostIp).await?;
                Ok(Value::Null)
            }
            "start_punch" => {
                let peer = payload
                    .get("peerSessionId")
                    .or_else(|| payload.get("peer_session_id"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .map(ToOwned::to_owned);
                if self.state.lock().await.is_host {
                    self.start_host_punch_for_peer(
                        peer.as_deref().ok_or("peerSessionId is required")?,
                    )
                    .await?;
                } else {
                    self.start_punch().await?;
                }
                Ok(Value::Null)
            }
            "start_tun_bridge" => {
                self.start_guest_tun().await?;
                Ok(Value::Null)
            }
            "request_relay" => {
                self.signal.send(ClientMessage::RelayRequest).await?;
                Ok(Value::Null)
            }
            "start_relay_tunnel" => {
                let relay = RelayInfo {
                    relay_addr: required_string(&payload, "relayAddr")?,
                    relay_quic_port: payload
                        .get("relayQuicPort")
                        .and_then(Value::as_u64)
                        .ok_or("relayQuicPort is required")?
                        as u16,
                    token: required_string(&payload, "token")?,
                };
                self.start_relay(relay).await?;
                Ok(Value::Null)
            }
            "get_tunnel_stats" => {
                serde_json::to_value(self.stats.get_stats().await).map_err(|e| e.to_string())
            }
            "reset_tunnel_stats" => {
                self.stats.clear().await;
                Ok(Value::Null)
            }
            "add_connection" => {
                let user = required_string(&payload, "userId")?;
                let mode = payload
                    .get("connectionMode")
                    .and_then(Value::as_str)
                    .unwrap_or("p2p")
                    .to_string();
                self.stats.add_connection(user, mode).await;
                Ok(Value::Null)
            }
            "remove_connection" => {
                self.stats
                    .remove_connection(&required_string(&payload, "userId")?)
                    .await;
                Ok(Value::Null)
            }
            "load_config" => {
                serde_json::to_value(self.config.read().await.clone()).map_err(|e| e.to_string())
            }
            "save_config" => {
                let value = payload.get("config").cloned().ok_or("config is required")?;
                let mut config: ClientConfig =
                    serde_json::from_value(value).map_err(|e| e.to_string())?;
                config.apply_mode_policy();
                config.save().map_err(|e| e.to_string())?;
                *self.config.write().await = config;
                Ok(Value::Null)
            }
            "get_network_info" => {
                self.emit(
                    "diag:progress",
                    json!({"progress": 20, "stage": "检测本机网络", "eta_seconds": 1}),
                );
                let local = tokio::task::spawn_blocking(network::detect_local_network)
                    .await
                    .map_err(|e| e.to_string())?;
                self.emit(
                    "diag:progress",
                    json!({"progress": 100, "stage": "诊断完成", "eta_seconds": 0}),
                );
                Ok(json!({
                    "nat_type": "待连接检测", "mapping_behavior": "--", "filtering_behavior": "--",
                    "port_pattern": "--", "confidence": "--", "external_ip": "0.0.0.0", "external_port": 0,
                    "upnp": false, "upnp_port": 0, "ipv6": local.ipv6_available,
                    "ipv6_addr": local.ipv6_addr, "local_ip": local.local_ip, "local_port": 0,
                    "stun_mappings": [], "stun_details": [], "network_priority": if local.ipv6_available { "ipv6" } else { "ipv4" }
                }))
            }
            _ => Err(format!("unsupported command: {}", command)),
        }
    }
}

fn required_string(payload: &Value, key: &str) -> Result<String, String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{} is required", key))
}

fn server_event_name(message: &ServerMessage) -> &'static str {
    match message {
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
    }
}

async fn resolve_ipv4(host: &str, port: u16) -> Result<SocketAddr, String> {
    let target = format!("{}:{}", host.trim(), port);
    if let Ok(address) = target.parse::<SocketAddr>() {
        return address
            .is_ipv4()
            .then_some(address)
            .ok_or_else(|| format!("relay address must be IPv4: {}", target));
    }
    for address in tokio::net::lookup_host(&target)
        .await
        .map_err(|e| e.to_string())?
    {
        if address.is_ipv4() {
            return Ok(address);
        }
    }
    Err(format!(
        "cannot resolve an IPv4 relay address for {}",
        target
    ))
}

/// Host 是否需要新建中继连接。
///
/// 房间里所有 Guest 共用 Host 这一条中继连接，而每个 Guest 回落中继都会
/// 触发一次 `RelayReady`。若 token 未变且连接仍可用，重连只会把正在经由
/// 它转发的其他 Guest 一起掐断，因此这里必须返回 false。
fn should_start_host_relay(
    active_token: Option<&str>,
    requested_token: &str,
    connection_present: bool,
    connection_alive: bool,
) -> bool {
    let same_token = active_token == Some(requested_token);
    !(same_token && (connection_alive || !connection_present))
}

#[cfg(test)]
mod tests {
    use super::should_start_host_relay;

    #[test]
    fn host_relay_is_idempotent_per_room_token() {
        // 首次请求：没有活动 token，必须建立
        assert!(should_start_host_relay(None, "room-a", false, false));
        // 同 token 且正在建立中（尚无连接对象）：不要重复发起
        assert!(!should_start_host_relay(
            Some("room-a"),
            "room-a",
            false,
            false
        ));
        // 同 token 且连接存活：复用，绝不能重连
        assert!(!should_start_host_relay(
            Some("room-a"),
            "room-a",
            true,
            true
        ));
        // 同 token 但连接已断：需要重建
        assert!(should_start_host_relay(
            Some("room-a"),
            "room-a",
            true,
            false
        ));
        // 换了房间（token 变化）：必须重建
        assert!(should_start_host_relay(
            Some("room-a"),
            "room-b",
            true,
            true
        ));
    }
}
