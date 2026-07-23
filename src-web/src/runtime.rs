use phantom_core::{
    config::ClientConfig, identity::Identity, network, puncher, signal, stats, tun_bridge, tunnel,
};
use phantom_protocol::{ClientMessage, IceCandidate, ServerMessage};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, watch, Mutex, RwLock};

#[derive(Clone, Debug, Serialize)]
pub struct UiEvent {
    pub event: String,
    pub data: Value,
}

#[derive(Clone)]
struct RelayInfo {
    room_code: String,
    relay_addr: String,
    relay_quic_port: u16,
    token: String,
}

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
    relay: Option<RelayInfo>,
    conn_manager: Option<Arc<tunnel::TunnelConnManager>>,
    host_endpoint: Option<quinn::Endpoint>,
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
            relay: None,
            conn_manager: None,
            host_endpoint: None,
            relay_host_conn: None,
            tun_bridge: None,
        }
    }
}

pub struct HeadlessRuntime {
    signal: Arc<signal::client::SignalClient>,
    stats: Arc<stats::StatsManager>,
    state: Mutex<RuntimeState>,
    config: RwLock<ClientConfig>,
    events: broadcast::Sender<UiEvent>,
    overlay_ip: watch::Sender<Option<Ipv4Addr>>,
    auto_host: AtomicBool,
    web_port: u16,
}

impl HeadlessRuntime {
    pub fn new(web_port: u16) -> Result<Arc<Self>, String> {
        phantom_core::ensure_rustls_crypto_provider()?;
        let config = ClientConfig::load();
        let data_dir = ClientConfig::config_path()
            .parent()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let identity = Arc::new(Identity::load_or_generate(&data_dir)?);
        let signal = Arc::new(signal::client::SignalClient::new(identity, config.dev_mode));
        let stats = Arc::new(stats::StatsManager::new(false));
        stats.clone().start_sampling_task();
        let (events, _) = broadcast::channel(512);
        let (overlay_ip, _) = watch::channel(None);
        Ok(Arc::new(Self {
            signal,
            stats,
            state: Mutex::new(RuntimeState::default()),
            config: RwLock::new(config),
            events,
            overlay_ip,
            auto_host: AtomicBool::new(false),
            web_port,
        }))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.events.subscribe()
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
            let _ = self.events.send(UiEvent {
                event: event.to_string(),
                data,
            });
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
                        println!();
                        println!("Room code:        {}", room_code);
                        println!("Host virtual IP:  {}", virtual_ip);
                        println!("Overlay WebUI:    http://{}:{}", virtual_ip, self.web_port);
                        println!();
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
                    .add_connection(peer_session_id, "p2p".into())
                    .await;
                if let Err(error) = self.start_punch().await {
                    self.emit("punch:phase", puncher::PunchPhase::Failed { reason: error });
                }
            }
            ServerMessage::PeerLeft {
                peer_session_id, ..
            } => {
                self.stats.remove_connection(&peer_session_id).await;
            }
            ServerMessage::RelayPreAllocated {
                room_code,
                relay_addr,
                relay_quic_port,
                token,
            } => {
                self.state.lock().await.relay = Some(RelayInfo {
                    room_code,
                    relay_addr,
                    relay_quic_port,
                    token,
                });
            }
            ServerMessage::RelayReady {
                room_code,
                relay_addr,
                relay_quic_port,
                token,
            } => {
                let relay = RelayInfo {
                    room_code,
                    relay_addr,
                    relay_quic_port,
                    token,
                };
                self.state.lock().await.relay = Some(relay.clone());
                if let Err(error) = self.start_relay(relay).await {
                    self.emit("tunnel:failed", json!({"mode": "Relay", "reason": error}));
                }
            }
            ServerMessage::PeerCandidates {
                peer_session_id,
                candidates,
                peer_nat_type,
                start_at_ms,
                ..
            } => {
                let runtime = self.clone();
                tokio::spawn(async move {
                    runtime
                        .handle_peer_candidates(
                            peer_session_id,
                            candidates,
                            peer_nat_type,
                            start_at_ms,
                        )
                        .await;
                });
            }
            ServerMessage::RoomClosed { .. } => self.reset_room().await,
            _ => {}
        }
        self.emit_status().await;
    }

    async fn start_punch(&self) -> Result<(), String> {
        let existing = {
            let state = self.state.lock().await;
            if state.is_host && !state.local_candidates.is_empty() {
                Some(state.local_candidates.clone())
            } else {
                None
            }
        };
        if let Some(candidates) = existing {
            self.signal
                .send(ClientMessage::IceCandidates {
                    candidates,
                    ufrag: String::new(),
                    pwd: String::new(),
                    nat_type: String::new(),
                })
                .await?;
            self.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
            return Ok(());
        }

        self.emit("punch:phase", puncher::PunchPhase::Probing);
        let (socket, candidates) = tokio::task::spawn_blocking(|| {
            let socket =
                network::bind_dual_stack_udp(0).map_err(|e| format!("bind ICE socket: {}", e))?;
            let (candidates, _, _, _) = puncher::gather_ice_candidates(&socket);
            Ok::<_, String>((Arc::new(socket), candidates))
        })
        .await
        .map_err(|e| e.to_string())??;
        {
            let mut state = self.state.lock().await;
            state.socket = Some(socket);
            state.local_candidates = candidates.clone();
        }
        self.signal
            .send(ClientMessage::IceCandidates {
                candidates,
                ufrag: String::new(),
                pwd: String::new(),
                nat_type: String::new(),
            })
            .await?;
        self.emit("punch:phase", puncher::PunchPhase::WaitingPeer);
        Ok(())
    }

    async fn handle_peer_candidates(
        self: Arc<Self>,
        peer_session_id: String,
        candidates: Vec<IceCandidate>,
        peer_nat_type: String,
        start_at_ms: u64,
    ) {
        let (socket, is_host) = {
            let state = self.state.lock().await;
            (state.socket.clone(), state.is_host)
        };
        let Some(socket) = socket else {
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: "ICE socket is not ready".into(),
                },
            );
            return;
        };
        tracing::info!(
            "[ICE] checking {} candidates, NAT={}",
            candidates.len(),
            peer_nat_type
        );
        self.emit("punch:phase", puncher::PunchPhase::Punching);
        let result = puncher::do_ice_punch(socket.clone(), candidates, start_at_ms).await;
        if !result.success {
            self.emit(
                "punch:phase",
                puncher::PunchPhase::Failed {
                    reason: result.reason,
                },
            );
            if let Some(relay) = self.state.lock().await.relay.clone() {
                if let Err(error) = self.start_relay(relay).await {
                    self.emit("tunnel:failed", json!({"mode": "Relay", "reason": error}));
                }
            }
            return;
        }

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
            if state.host_endpoint.is_none() {
                match socket
                    .try_clone()
                    .map_err(|e| e.to_string())
                    .and_then(tunnel::create_host_endpoint)
                {
                    Ok(endpoint) => {
                        let task_endpoint = endpoint.clone();
                        let stats = self.stats.clone();
                        let tun = state.tun_bridge.clone();
                        tokio::spawn(async move {
                            let _ = tunnel::start_host_tunnel(
                                task_endpoint,
                                stats,
                                Arc::new(Mutex::new(HashMap::new())),
                                tun,
                            )
                            .await;
                        });
                        state.host_endpoint = Some(endpoint);
                    }
                    Err(error) => {
                        drop(state);
                        self.emit("tunnel:failed", json!({"mode": "P2P", "reason": error}));
                        return;
                    }
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
        let (is_host, tun) = {
            let state = self.state.lock().await;
            (state.is_host, state.tun_bridge.clone())
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
            let connection = tunnel::connect_relay_quic_host(
                address,
                relay.token,
                self.stats.clone(),
                user,
                tun,
            )
            .await?;
            self.state.lock().await.relay_host_conn = Some(connection);
        } else {
            let connection =
                tunnel::connect_relay_quic_guest(address, relay.token, self.stats.clone(), user)
                    .await?;
            self.state.lock().await.conn_manager = Some(tunnel::TunnelConnManager::new(connection));
            self.start_guest_tun().await?;
        }
        self.emit("tunnel:started", "Relay");
        Ok(())
    }

    async fn start_guest_tun(&self) -> Result<(), String> {
        let (subnet, virtual_ip, host_ip, connection, already_started) = {
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
            )
        };
        if already_started {
            return Ok(());
        }
        let connection = connection.ok_or("QUIC connection is not ready")?;
        let bridge = tun_bridge::TunBridge::start(&subnet, &virtual_ip, &host_ip, connection)
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
                    let url = phantom_core::config::runtime_signal_server(requested);
                    self.signal.connect(url).await;
                }
                for event in self.snapshot().await {
                    let _ = self.events.send(event);
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
                self.start_punch().await?;
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
                    room_code: self
                        .state
                        .lock()
                        .await
                        .room_code
                        .clone()
                        .unwrap_or_default(),
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
        ServerMessage::Pong => "signal:pong",
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
        ServerMessage::PeerCandidates { .. } => "signal:peer_candidates",
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
