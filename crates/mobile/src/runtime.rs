//! 移动端会话编排。
//!
//! # 为什么这份代码在 `crates/mobile` 而不是 `crates/core`
//!
//! 编排逻辑（连信令 → 探测 → 上报画像 → 收策略 → 打洞 → 建隧道 → 落中继）
//! 目前在 `src-tauri/lib.rs` 与 `src-web/runtime.rs` 里已经各有一份。把它
//! 提取到 core 让三端共用，技术上更"干净"，但那要改动正在发版的桌面端代码。
//!
//! 这里选择第三份。理由是取舍的形状变了：
//!
//! - **编排是浅的**。它只是把 core 的能力按顺序接起来，没有算法。
//! - **引擎是深的**。打洞的 8 策略矩阵、NAT 分类、`repair/` 的反馈控制器、
//!   overlay 加密 —— 这些全部直接用 `phantom-core`，与 PC 同一份代码。
//!
//! 旧安卓端死于用 Kotlin 复刻了**引擎**（2 类 NAT、无策略矩阵、明文握手），
//! 跟不上 PC 的迭代。重复**编排**没有这个风险：协议改版是低频事件，而算法
//! 调参是高频的，高频的那部分共享了。
//!
//! 而且 `crates/mobile` 不在 `src-tauri` / `src-web` 的依赖图里 ——
//! 这里写错了，结构上也波及不到 PC。
//!
//! 等 Android 跑稳，把这份编排上提到 core 再让 src-web 切过来，是一个
//! 可独立验证的小动作。路留着。

use crate::host::{RuntimeHost, TunRequest};
use phantom_core::{
    config::ClientConfig, identity::Identity, punch, puncher, signal, stats, tun_bridge, tunnel,
};
use phantom_protocol::{
    ClientMessage, IceCandidate, NatProfile, PunchParams, PunchStrategy, ServerMessage,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

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

/// 每个对端一套打洞会话（三阶段状态机在 phantom-core 里，与 PC 共用）
type PunchSessions = HashMap<String, punch::Session>;

#[derive(Default)]
struct RuntimeState {
    authenticated_user: Option<String>,
    room_code: Option<String>,
    is_host: bool,
    subnet: String,
    virtual_ip: String,
    host_virtual_ip: String,
    socket: Option<Arc<UdpSocket>>,
    local_candidates: Vec<IceCandidate>,
    punch_sessions: PunchSessions,
    /// 打洞阶段协商出的 overlay 会话密钥。
    /// P2P 与中继两条路径共用同一份——中继只做盲转发，看不到明文。
    peer_crypto: Option<Arc<phantom_core::crypto::SessionCrypto>>,
    relay: Option<RelayInfo>,
    conn_manager: Option<Arc<tunnel::TunnelConnManager>>,
    host_peers: HashMap<String, HostPeer>,
    host_ice_tasks: HashMap<String, tokio::task::JoinHandle<()>>,
    relay_host_conn: Option<quinn::Connection>,
    tun_bridge: Option<Arc<tun_bridge::TunBridge>>,
    /// 中继连接的 token。配合 `should_start_host_relay` 保证"同 token 且连接
    /// 存活就不重连"——否则多 guest 房间里每次 RelayReady 都会拆掉正在服务
    /// 其他 guest 的那条中继连接。
    relay_host_token: Option<String>,
}

pub struct SessionRuntime {
    host: Arc<dyn RuntimeHost>,
    signal: Arc<signal::client::SignalClient>,
    stats: Arc<stats::StatsManager>,
    state: Mutex<RuntimeState>,
    config: RwLock<ClientConfig>,
    /// 隧道是否已经在跑。用于判断 VpnService 该不该继续持有前台通知。
    tunnel_live: AtomicBool,
}

impl SessionRuntime {
    pub fn new(host: Arc<dyn RuntimeHost>) -> Result<Arc<Self>, String> {
        phantom_core::ensure_rustls_crypto_provider()?;

        // 路径必须在读配置和身份之前注入：默认的 dirs::config_dir()
        // 在 Android 上会落到不可写的 /。
        phantom_core::config::set_config_dir(host.data_dir());

        let config = ClientConfig::load();
        let identity = Arc::new(Identity::load_or_generate(&host.data_dir())?);
        let signal = Arc::new(signal::client::SignalClient::new(identity, config.dev_mode));
        let stats = Arc::new(stats::StatsManager::new(false));
        stats.clone().start_sampling_task();

        Ok(Arc::new(Self {
            host,
            signal,
            stats,
            state: Mutex::new(RuntimeState::default()),
            config: RwLock::new(config),
            tunnel_live: AtomicBool::new(false),
        }))
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    pub async fn connect_signal(self: &Arc<Self>, signal_url: String) {
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

    pub async fn create_room(&self) -> Result<(), String> {
        // 一次连接一份干净日志：把上一段会话归档，从空文件重新开始。
        phantom_core::logging::begin_session("host");
        self.reset_room().await;
        self.stats.set_host_mode(true);
        self.state.lock().await.is_host = true;
        self.signal.send(ClientMessage::CreateRoom).await
    }

    pub async fn join_room(&self, room_code: String) -> Result<(), String> {
        phantom_core::logging::begin_session(&room_code);
        self.reset_room().await;
        self.stats.set_host_mode(false);
        self.signal
            .send(ClientMessage::JoinRoom { room_code })
            .await
    }

    pub async fn leave_room(&self) -> Result<(), String> {
        let is_host = self.state.lock().await.is_host;
        let message = if is_host {
            ClientMessage::CloseRoom
        } else {
            ClientMessage::LeaveRoom
        };
        let result = self.signal.send(message).await;
        self.reset_room().await;
        result
    }

    pub async fn disconnect(&self) {
        self.reset_room().await;
        self.signal.disconnect().await;
    }

    pub async fn request_log_upload(&self, reason: String) -> Result<(), String> {
        self.signal
            .send(ClientMessage::RequestLogUpload { reason })
            .await
    }

    pub async fn stats_snapshot(&self) -> stats::StatsResponse {
        self.stats.get_stats().await
    }

    pub fn is_tunnel_live(&self) -> bool {
        self.tunnel_live.load(Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // 事件
    // -----------------------------------------------------------------------

    fn emit<T: Serialize>(&self, event: &str, payload: T) {
        match serde_json::to_value(payload) {
            Ok(data) => self.host.emit(event, data),
            Err(e) => tracing::warn!("[事件] {} 序列化失败: {}", event, e),
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

    // -----------------------------------------------------------------------
    // 信令消息
    // -----------------------------------------------------------------------

    async fn handle_server_message(self: &Arc<Self>, message: ServerMessage) {
        self.emit(server_event_name(&message), &message);

        match message {
            ServerMessage::AuthOk { user_id } => {
                self.state.lock().await.authenticated_user = Some(user_id);
            }

            ServerMessage::RoomCreated {
                room_code,
                subnet,
                virtual_ip,
            } => {
                self.tear_down_connections().await;
                {
                    let mut state = self.state.lock().await;
                    state.room_code = Some(room_code.clone());
                    state.is_host = true;
                    state.subnet = subnet.clone();
                    state.virtual_ip = virtual_ip.clone();
                    state.host_virtual_ip = virtual_ip.clone();
                }

                match self.start_host_tun(&subnet, &virtual_ip).await {
                    Ok(()) => {
                        self.emit(
                            "tun:ready",
                            json!({
                                "my_ip": virtual_ip,
                                "host_ip": virtual_ip,
                                "subnet": subnet,
                            }),
                        );
                        // Host 的网卡就绪之前不能放 guest 进来 ——
                        // TunBridge 是先建 TUN 再接对端，房间开了但 TUN 没起，
                        // guest 接进来会没有落点。
                        let _ = self.signal.send(ClientMessage::HostReady).await;
                    }
                    Err(error) => {
                        tracing::error!("[TUN] Host 虚拟网卡建立失败: {}", error);
                        self.emit("tun:failed", json!({ "reason": error }));
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
                let mut state = self.state.lock().await;
                if let Some(task) = state.host_ice_tasks.remove(&peer_session_id) {
                    task.abort();
                }
                if let Some(peer) = state.host_peers.remove(&peer_session_id) {
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

    // -----------------------------------------------------------------------
    // 虚拟网卡
    //
    // 与桌面端唯一实质不同的一段：core 不能自己建网卡，只有 VpnService 能。
    // 所以每次要建 TUN 之前，先算好参数让宿主去建，把 fd 交进 core，
    // 再走 TunBridge —— 后者会通过 tun_android 认领那个 fd。
    // -----------------------------------------------------------------------

    /// 把 fd 交给 core，失败时负责清理，避免泄漏。
    async fn provision_tun(&self, request: TunRequest) -> Result<(), String> {
        let fd = self.host.establish_tun(&request)?;
        phantom_core::tun::android_provide_tun_fd(fd);
        Ok(())
    }

    fn tun_params(subnet: &str, address: &str, extra_route: Option<(String, u8)>) -> TunRequest {
        // subnet 是三段前缀（如 "10.66.0"），不是 CIDR —— 与 core 的
        // parse_network 约定一致。
        let network = format!("{}.0", subnet.trim());
        let mut routes = vec![(network, 24u8)];
        if let Some(route) = extra_route {
            routes.push(route);
        }

        // Host 拿固定 IP 时它落在子网之外，用 /32；其余用 /24。
        let in_subnet = address
            .rsplit_once('.')
            .map(|(prefix, _)| prefix == subnet.trim())
            .unwrap_or(false);

        TunRequest {
            address: address.to_string(),
            prefix_len: if in_subnet { 24 } else { 32 },
            routes,
            mtu: tun_bridge::TUN_MTU,
        }
    }

    async fn start_host_tun(&self, subnet: &str, virtual_ip: &str) -> Result<(), String> {
        self.provision_tun(Self::tun_params(subnet, virtual_ip, None))
            .await?;

        match tun_bridge::TunBridge::start_host(subnet, virtual_ip).await {
            Ok(bridge) => {
                self.state.lock().await.tun_bridge = Some(bridge);
                self.tunnel_live.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                // 网卡已经建了但 bridge 没起来，fd 还在槽位里，必须丢掉，
                // 否则下一次建隧道会认领到一个陈旧的 fd。
                phantom_core::tun::android_discard_tun_fd();
                Err(e.to_string())
            }
        }
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

        let connection = connection.ok_or("QUIC 连接尚未就绪")?;
        // 没有会话密钥就不建隧道——绝不退回明文传输
        let crypto = crypto.ok_or("overlay 会话密钥尚未协商完成")?;

        // Host 拿固定 IP 时落在子网外，guest 需要一条通往它的 /32 路由。
        // VpnService 的路由必须在 establish 之前给全，事后无法追加。
        let host_outside = !host_ip.starts_with(&format!("{}.", subnet.trim()));
        let extra = host_outside.then(|| (host_ip.clone(), 32u8));
        self.provision_tun(Self::tun_params(&subnet, &virtual_ip, extra))
            .await?;

        // Guest 只有一条对端连接，取它作为流量与丢包统计的归属。
        // 没有它的话 tun_bridge 无处上报，带宽会一直显示 0。
        let peer_stats = self
            .stats
            .first_connection_id()
            .await
            .map(|user| (self.stats.clone(), user));

        let bridge = match tun_bridge::TunBridge::start(
            &subnet,
            &virtual_ip,
            &host_ip,
            connection,
            crypto,
            peer_stats,
        )
        .await
        {
            Ok(bridge) => bridge,
            Err(e) => {
                phantom_core::tun::android_discard_tun_fd();
                return Err(e.to_string());
            }
        };

        self.state.lock().await.tun_bridge = Some(bridge);
        self.tunnel_live.store(true, Ordering::Relaxed);
        self.emit(
            "tun:ready",
            json!({"my_ip": virtual_ip, "host_ip": host_ip, "subnet": subnet}),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 打洞（三阶段，状态机在 phantom-core 里，与 PC 共用）
    // -----------------------------------------------------------------------

    /// 取服务端下发的 STUN 列表（自建优先）。
    ///
    /// 必须等配置到位再探测：拿空列表跑完只会得到 class=Unknown、没有 srflx
    /// 候选，打洞从一开始就注定失败。
    async fn stun_servers(&self) -> Vec<(String, u16)> {
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

    /// **阶段一**：探测 NAT 画像并上报。
    async fn begin_punch(&self, target_peer: Option<String>) -> Result<(), String> {
        let stun = self.stun_servers().await;
        let rtt = self.signal.signal_rtt_ms();
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
        let has_existing = {
            let state = self.state.lock().await;
            state.is_host && !state.local_candidates.is_empty()
        };
        if has_existing {
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

        // 开发者模式的强制中继：会话密钥在阶段二 on_plan 就已经通过双方交换的
        // 临时公钥派生完毕，跟真的去打洞无关——这里直接跳过 session.run()，
        // 当成一次打洞失败处理，复用下面已有的"失败就回退中继"逻辑。
        if self.config.read().await.force_relay_mode {
            self.state.lock().await.peer_crypto = session.crypto();
            tracing::warn!("[开发者模式] 强制中继已开启，跳过 P2P 打洞");
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: "开发者模式已开启强制中继".into(),
                },
            );
            if let Some(relay) = self.state.lock().await.relay.clone() {
                if let Err(error) = self.start_relay(relay).await {
                    self.emit("tunnel:failed", json!({"mode": "Relay", "reason": error}));
                }
            }
            return;
        }

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
            // 打洞失败时也要写回密钥——接下来走中继回退，中继同样需要它
            self.state.lock().await.peer_crypto = outcome.crypto.clone();
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

        let peer_addr = success.peer_addr.to_string();
        self.emit(
            "punch:phase",
            puncher::PunchPhase::Success {
                latency_ms: success.rtt_ms,
            },
        );
        self.stats
            .add_connection(peer_session_id.clone(), "p2p".into())
            .await;

        if is_host {
            self.start_host_p2p_tunnel(peer_session_id, peer_addr, socket)
                .await;
        } else {
            self.start_guest_p2p_tunnel(peer_session_id, peer_addr, socket)
                .await;
        }
    }

    async fn start_host_p2p_tunnel(
        &self,
        peer_session_id: String,
        peer_addr: String,
        socket: Arc<UdpSocket>,
    ) {
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
                let peer_map = Arc::new(std::sync::Mutex::new(HashMap::from([(
                    peer_addr,
                    peer_session_id.clone(),
                )])));
                tokio::spawn(async move {
                    let _ = tunnel::start_host_tunnel(task_endpoint, stats, peer_map, tun, crypto)
                        .await;
                });
                if let Some(peer) = state.host_peers.get_mut(&peer_session_id) {
                    peer.endpoint = Some(endpoint);
                }
                drop(state);
                self.tunnel_live.store(true, Ordering::Relaxed);
                self.emit("tunnel:started", "P2P");
            }
            Err(error) => {
                drop(state);
                self.emit("tunnel:failed", json!({"mode": "P2P", "reason": error}));
            }
        }
    }

    async fn start_guest_p2p_tunnel(
        &self,
        peer_session_id: String,
        peer_addr: String,
        socket: Arc<UdpSocket>,
    ) {
        let peer: SocketAddr = match peer_addr.parse() {
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
            self.emit("tun:failed", json!({ "reason": error }));
            return;
        }
        self.emit("tunnel:started", "P2P");
    }

    // -----------------------------------------------------------------------
    // 中继
    // -----------------------------------------------------------------------

    async fn start_relay(&self, relay: RelayInfo) -> Result<(), String> {
        let address = resolve_ipv4(&relay.relay_addr, relay.relay_quic_port).await?;
        let (is_host, tun, crypto, active_token, conn_alive) = {
            let state = self.state.lock().await;
            (
                state.is_host,
                state.tun_bridge.clone(),
                state.peer_crypto.clone(),
                state.relay_host_token.clone(),
                state
                    .relay_host_conn
                    .as_ref()
                    .map(|c| c.close_reason().is_none())
                    .unwrap_or(false),
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
            // 同 token 且连接仍存活就不重连 —— 多 guest 房间里每次 RelayReady
            // 都新建连接的话，会拆掉正在服务其他 guest 的那条。
            if !should_start_host_relay(active_token.as_deref(), &relay.token, conn_alive) {
                tracing::info!("[中继] Host 已有同 token 的存活连接，跳过重连");
                return Ok(());
            }

            let token = relay.token.clone();
            self.state.lock().await.relay_host_token = Some(token.clone());

            let connection = match tunnel::connect_relay_quic_host(
                address,
                relay.token,
                self.stats.clone(),
                user,
                tun,
                crypto,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    // 失败要清空 token，否则守卫会认定"同 token 建立中"而永远拒绝重连
                    self.state.lock().await.relay_host_token = None;
                    return Err(e);
                }
            };

            let mut state = self.state.lock().await;
            if state.relay_host_token.as_deref() == Some(token.as_str()) {
                state.relay_host_conn = Some(connection);
            } else {
                // 建连期间 token 换了，这条已经过期
                connection.close(0u32.into(), b"stale relay token");
            }
        } else {
            let connection =
                tunnel::connect_relay_quic_guest(address, relay.token, self.stats.clone(), user)
                    .await?;
            let existing = self.state.lock().await.conn_manager.clone();
            if let Some(manager) = existing {
                // 保留已建好的 TUN 与活跃的应用流；新包切到中继上走
                manager.upgrade(connection).await;
            } else {
                self.state.lock().await.conn_manager =
                    Some(tunnel::TunnelConnManager::new(connection));
            }
            self.start_guest_tun().await?;
        }

        self.tunnel_live.store(true, Ordering::Relaxed);
        self.emit("tunnel:started", "Relay");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 清理
    // -----------------------------------------------------------------------

    /// 关掉所有连接，但保留房间信息。Host 换地址时用。
    async fn tear_down_connections(&self) {
        let mut state = self.state.lock().await;
        if let Some(bridge) = state.tun_bridge.take() {
            bridge.close().await;
        }
        if let Some(manager) = state.conn_manager.take() {
            manager.close().await;
        }
        for (_, peer) in std::mem::take(&mut state.host_peers) {
            if let Some(endpoint) = peer.endpoint {
                endpoint.close(0u32.into(), b"host address changed");
            }
        }
        for (_, task) in std::mem::take(&mut state.host_ice_tasks) {
            task.abort();
        }
        if let Some(connection) = state.relay_host_conn.take() {
            connection.close(0u32.into(), b"host address changed");
        }
        state.relay_host_token = None;
    }

    async fn reset_room(&self) {
        self.tear_down_connections().await;
        // 网卡可能已经建了但没被 TunBridge 认领，一并丢掉避免 fd 泄漏
        phantom_core::tun::android_discard_tun_fd();

        let mut state = self.state.lock().await;
        let authenticated_user = state.authenticated_user.clone();
        *state = RuntimeState {
            authenticated_user,
            ..RuntimeState::default()
        };
        drop(state);

        self.tunnel_live.store(false, Ordering::Relaxed);
        self.stats.clear().await;
    }

    /// 收到上传凭据后打包并上传日志。
    ///
    /// 打包与 HTTP 传输都是阻塞操作，放到 blocking 线程池，
    /// 避免拖住信令消息循环。
    async fn upload_logs(&self, upload_url: String, reason: String) {
        let dir = self.host.log_dir();
        let result = tokio::task::spawn_blocking(move || {
            let uploader = phantom_core::log_upload::LogUploader::new(&dir);
            // 先补投历史失败的包——它们往往正是"网络有问题"那次的日志
            uploader.flush_pending();
            uploader.upload_now(&upload_url, &reason)
        })
        .await;

        match result {
            Ok(Ok(bytes)) => self.emit("log:uploaded", json!({ "bytes": bytes })),
            Ok(Err(e)) => {
                tracing::warn!("[日志上报] {}", e);
                self.emit("log:upload_failed", json!({ "reason": e }));
            }
            Err(e) => tracing::warn!("[日志上报] 任务失败: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// Host 中继连接的重连守卫。
///
/// 纯函数，便于单测。规则：同 token 且连接存活 → 不重连。
fn should_start_host_relay(active_token: Option<&str>, requested: &str, alive: bool) -> bool {
    match active_token {
        Some(token) if token == requested && alive => false,
        _ => true,
    }
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
            .ok_or_else(|| format!("中继地址必须是 IPv4: {}", target));
    }
    for address in tokio::net::lookup_host(&target)
        .await
        .map_err(|e| e.to_string())?
    {
        if address.is_ipv4() {
            return Ok(address);
        }
    }
    Err(format!("无法把 {} 解析成 IPv4 中继地址", target))
}

#[cfg(test)]
mod tests {
    use super::should_start_host_relay;

    #[test]
    fn host_relay_guard() {
        // 没有活动 token —— 必须建连
        assert!(should_start_host_relay(None, "t1", false));
        // token 变了 —— 必须重连
        assert!(should_start_host_relay(Some("t0"), "t1", true));
        // 同 token 但连接已死 —— 必须重连
        assert!(should_start_host_relay(Some("t1"), "t1", false));
        // 同 token 且存活 —— 不能重连，否则会拆掉正在服务其他 guest 的那条
        assert!(!should_start_host_relay(Some("t1"), "t1", true));
    }
}
