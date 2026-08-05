//! 幻梦P2P 信令服务器
//!
//! 基于 WebSocket 的信令服务器，负责：
//! 1. 管理客户端连接（Session）
//! 2. 管理房间（Room）的创建、加入、离开、关闭
//! 3. 生成全局唯一的配对码
//! 4. 在 host 和 guest 之间转发信令消息
//!
//! 架构：
//! - 每个 WebSocket 连接在独立的 tokio 任务中处理
//! - 所有共享状态通过 Arc<Mutex<AppState>> 管理
//! - 消息使用 MessagePack 序列化（通过 phantom-protocol crate）

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use phantom_protocol::{ClientMessage, ServerMessage};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};
use uuid::Uuid;

mod admin;
mod config;
mod database;
mod log_upload;
mod relay;
mod stun_server;

// ============================================================
// 数据结构
// ============================================================

/// 一个客户端连接的 Session
struct Session {
    /// 唯一会话 ID
    session_id: String,
    /// 向该客户端发送消息的通道
    sender: mpsc::UnboundedSender<ServerMessage>,
    /// 当前所在的房间配对码（None = 不在任何房间）
    room_code: Option<String>,
    /// 在房间中的角色
    role: Option<Role>,
    /// 客户端地址
    addr: SocketAddr,
    /// 是否已通过鉴权
    authenticated: bool,
    /// 待验证的 nonce（发送 AuthChallenge 后保存）
    auth_nonce: Option<[u8; 32]>,
    /// 已验证的公钥
    public_key: Option<[u8; 32]>,
    /// Stable user ID: the complete Ed25519 public key encoded as hex.
    user_id: Option<String>,
    /// 当前房间内由信令服务器分配的虚拟 IP
    virtual_ip: Option<String>,
    /// 最后活动时间（用于心跳超时检测）
    last_activity: tokio::time::Instant,
    /// 连接建立时间（用于管理面板展示在线时长）
    connected_at: tokio::time::Instant,
    /// 客户端上报的最终连接模式（"p2p" / "relay"），仅供管理面板展示，
    /// 不作为业务逻辑判断依据（打洞可能在中继预分配后仍然成功）
    connection_mode: Option<String>,
}

/// 房间角色
#[derive(Debug, Clone, PartialEq)]
enum Role {
    Host,
    Guest,
}

/// 房间状态
#[derive(Debug, Clone, PartialEq)]
enum RoomState {
    /// 刚创建，等待 Guest 加入
    Created,
    /// 等待 Guest 加入
    WaitingGuest,
    /// 中继中
    Relaying {
        /// 中继 token
        token: String,
        /// QUIC 中继端口
        quic_port: u16,
    },
    /// 失败
    Failed {
        /// 失败原因
        reason: String,
    },
}

/// 一端在打洞会话中的状态
#[derive(Clone, Default)]
struct PunchSide {
    /// 阶段一上报的 NAT 画像
    profile: Option<phantom_protocol::NatProfile>,
    /// 阶段一的基础候选（host + srflx）
    base_candidates: Vec<phantom_protocol::IceCandidate>,
    /// 阶段二的策略候选（预测/撒网目标、新建 socket 的映射）
    strategy_candidates: Vec<phantom_protocol::IceCandidate>,
    /// 是否需要走阶段二；由策略决定
    needs_strategy: bool,
    /// 阶段二是否已上报
    strategy_reported: bool,
}

impl PunchSide {
    /// 该端的候选是否已集齐，可以进入阶段三
    fn ready_for_start(&self) -> bool {
        self.profile.is_some() && (!self.needs_strategy || self.strategy_reported)
    }

    /// 下发给对端的完整候选集
    fn all_candidates(&self) -> Vec<phantom_protocol::IceCandidate> {
        let mut v = self.base_candidates.clone();
        v.extend(self.strategy_candidates.iter().cloned());
        v
    }
}

/// 一对 Host↔Guest 的打洞会话（三阶段状态机）
///
/// ```text
/// 阶段一  双方 NatProfileReport  →  服务端选策略  →  下发 PunchPlan
/// 阶段二  需要新建 socket 的一方上报 StrategyCandidates（简单组合跳过）
/// 阶段三  双方候选集齐  →  下发 PunchStart（统一起始时刻）
/// ```
#[derive(Clone)]
struct PunchSession {
    /// 本次尝试的唯一 ID，贯穿遥测
    attempt_id: String,
    host: PunchSide,
    guest: PunchSide,
    /// 计划是否已下发（避免重复下发）
    plan_sent: bool,
    /// 是否已下发 PunchStart（避免重复触发）
    started: bool,
    created_at: std::time::Instant,
}

impl PunchSession {
    fn new() -> Self {
        Self {
            attempt_id: Uuid::new_v4().to_string(),
            host: PunchSide::default(),
            guest: PunchSide::default(),
            plan_sent: false,
            started: false,
            created_at: std::time::Instant::now(),
        }
    }

    fn side_mut(&mut self, is_host: bool) -> &mut PunchSide {
        if is_host {
            &mut self.host
        } else {
            &mut self.guest
        }
    }
}

/// 一个房间
struct Room {
    /// 配对码
    code: String,
    /// Host 的 session_id
    host_session_id: String,
    /// 虚拟子网段（如 "10.0.1" 表示 10.0.1.0/24）
    subnet: String,
    /// Host 在虚拟子网内固定使用的地址
    host_virtual_ip: String,
    /// Guest 的 session_id 集合
    guests: HashSet<String>,
    /// 创建时间
    created_at: std::time::Instant,
    /// 房间状态
    state: RoomState,
    /// 打洞会话：key 为 guest_session_id（一个 Host 对多个 Guest，各自独立一套）
    punch_sessions: HashMap<String, PunchSession>,
}

/// 全局共享状态
struct AppState {
    /// session_id -> Session
    sessions: HashMap<String, Session>,
    /// room_code -> Room
    rooms: HashMap<String, Room>,
    /// 已用房间码（防冲突）
    used_codes: HashSet<String>,
    /// 会话自增序号
    next_session_seq: u64,
    /// 子网自增计数器（10.0.1, 10.0.2, ...）
    subnet_counter: u32,
    /// 创建房间限流：ip -> (count, last_reset)
    rate_limit_create: HashMap<String, (u32, std::time::Instant)>,
    /// 连接限流：ip -> active count
    rate_limit_connections: HashMap<String, u32>,
    /// 中继注册表
    relay_registry: relay::SharedRegistry,
    /// 日志上传凭据注册表（未启用时为 None）
    log_uploads: Option<log_upload::UploadRegistry>,
    /// 当前获准借用中继补包的房间。
    ///
    /// 中继的硬约束是带宽，用并发授权数给它封顶——见
    /// [`config::RelayConfig::max_assist_rooms`]。
    relay_assist_rooms: HashSet<String>,
    /// 运行时配置
    config: Arc<config::ServerConfig>,
}

type SharedState = Arc<Mutex<AppState>>;

/// 单 IP 活跃信令连接上限。
///
/// 说明：多人在同一 NAT（例如同一校园网/热点）下会共享公网 IP，
/// 上限过低会导致第 3 人及后续被误判为滥用而拒绝连接。
const MAX_ACTIVE_CONNECTIONS_PER_IP: u32 = 32;
/// 会话心跳超时阈值（秒）
/// PC 客户端每 15s 发一次应用层 Ping，Android 每 10s 发一次。
/// 取 30s 给网络抖动留一个完整周期的冗余。
// Clients ping every 10-15s. Keep three missed heartbeats before tearing down
// a session so a sleeping Wi-Fi/mobile radio does not destroy a long-running
// headless Host room.
const SESSION_HEARTBEAT_TIMEOUT_SECS: u64 = 90;
/// 会话超时扫描周期（秒）
const SESSION_SWEEP_INTERVAL_SECS: u64 = 5;

impl AppState {
    fn new(
        relay_registry: relay::SharedRegistry,
        log_uploads: Option<log_upload::UploadRegistry>,
        config: Arc<config::ServerConfig>,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            rooms: HashMap::new(),
            used_codes: HashSet::new(),
            next_session_seq: 1,
            subnet_counter: 0,
            rate_limit_create: HashMap::new(),
            rate_limit_connections: HashMap::new(),
            relay_registry,
            log_uploads,
            relay_assist_rooms: HashSet::new(),
            config,
        }
    }

    fn next_session_id(&mut self) -> String {
        let id = format!("s_{:06}", self.next_session_seq);
        self.next_session_seq += 1;
        id
    }

    fn allocate_subnet(&mut self) -> String {
        self.subnet_counter += 1;
        format!("10.0.{}", self.subnet_counter)
    }

    fn generate_room_code(&mut self) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        loop {
            let mut rng = rand::thread_rng();
            let code: String = (0..6)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            if self.used_codes.insert(code.clone()) {
                return code;
            }
        }
    }
}

fn decrement_ip_connection_counter(st: &mut AppState, ip_str: &str) {
    if let Some(count) = st.rate_limit_connections.get_mut(ip_str) {
        if *count > 1 {
            *count -= 1;
        } else {
            st.rate_limit_connections.remove(ip_str);
        }
    }
}

/// 处理单个 WebSocket 连接
async fn handle_connection(stream: TcpStream, addr: SocketAddr, state: SharedState) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("[连接] {} WebSocket 握手失败: {}", addr, e);
            return;
        }
    };

    info!("[连接] 新连接来自 {}", addr);
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    let auth_nonce: [u8; 32] = rand::thread_rng().r#gen();

    let session_id = {
        let mut st = state.lock().await;

        // 连接限制：单 IP 活跃连接数上限（防滥用）
        let ip_str = addr.ip().to_string();
        let conn_count = st.rate_limit_connections.entry(ip_str.clone()).or_insert(0);
        if *conn_count >= MAX_ACTIVE_CONNECTIONS_PER_IP {
            warn!(
                "[速率限制] {} 超过最大连接数限制 ({})",
                addr, MAX_ACTIVE_CONNECTIONS_PER_IP
            );
            None
        } else {
            *conn_count += 1;

            let sid = st.next_session_id();
            st.sessions.insert(
                sid.clone(),
                Session {
                    session_id: sid.clone(),
                    sender: tx.clone(),
                    room_code: None,
                    role: None,
                    addr,
                    authenticated: false,
                    auth_nonce: Some(auth_nonce),
                    public_key: None,
                    user_id: None,
                    virtual_ip: None,
                    last_activity: tokio::time::Instant::now(),
                    connected_at: tokio::time::Instant::now(),
                    connection_mode: None,
                },
            );
            Some(sid)
        }
    };

    let Some(session_id) = session_id else {
        let _ = ws_sink.send(Message::Close(None)).await;
        return;
    };

    info!("[Session] {} 已注册 ({})", session_id, addr);

    // 发送 Welcome
    let welcome = ServerMessage::Welcome {
        session_id: session_id.clone(),
        protocol_version: phantom_protocol::PROTOCOL_VERSION,
    };
    match phantom_protocol::serialize(&welcome) {
        Ok(bytes) => {
            if let Err(e) = ws_sink.send(Message::Binary(bytes.into())).await {
                error!("[Session] {} 发送 Welcome 失败: {}", session_id, e);
                cleanup_session(&session_id, &state).await;
                return;
            }
        }
        Err(e) => {
            error!("[Session] {} 序列化 Welcome 失败: {}", session_id, e);
            cleanup_session(&session_id, &state).await;
            return;
        }
    }

    // 立即发送 AuthChallenge
    let auth_challenge = ServerMessage::AuthChallenge { nonce: auth_nonce };
    match phantom_protocol::serialize(&auth_challenge) {
        Ok(bytes) => {
            if let Err(e) = ws_sink.send(Message::Binary(bytes.into())).await {
                error!("[Session] {} 发送 AuthChallenge 失败: {}", session_id, e);
                cleanup_session(&session_id, &state).await;
                return;
            }
        }
        Err(e) => {
            error!("[Session] {} 序列化 AuthChallenge 失败: {}", session_id, e);
            cleanup_session(&session_id, &state).await;
            return;
        }
    }
    info!("[鉴权] {} 已发送 AuthChallenge", session_id);

    // 发送循环
    let sid_for_send = session_id.clone();
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match phantom_protocol::serialize(&msg) {
                Ok(bytes) => {
                    if ws_sink.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("[Session] {} 序列化失败: {}", sid_for_send, e);
                }
            }
        }
    });

    // 接收循环
    let sid_for_recv = session_id.clone();
    let state_for_recv = Arc::clone(&state);
    let recv_task = tokio::spawn(async move {
        while let Some(msg_result) = ws_stream.next().await {
            match msg_result {
                Ok(Message::Binary(data)) => {
                    info!(
                        "[Session] {} 收到二进制消息，大小: {} 字节",
                        sid_for_recv,
                        data.len()
                    );
                    match phantom_protocol::deserialize::<ClientMessage>(&data) {
                        Ok(client_msg) => {
                            info!("[Session] {} 收到消息: {:?}", sid_for_recv, client_msg);
                            handle_client_message(&sid_for_recv, client_msg, &state_for_recv).await;
                        }
                        Err(e) => {
                            warn!(
                                "[Session] {} 反序列化失败: {} ({}字节)",
                                sid_for_recv,
                                e,
                                data.len()
                            );
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let _ = data;
                    // WebSocket 帧级 PING 同样计为活跃（防其他客户端使用帧级 Ping）
                    let mut st = state_for_recv.lock().await;
                    if let Some(session) = st.sessions.get_mut(&sid_for_recv) {
                        session.last_activity = tokio::time::Instant::now();
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("[Session] {} 主动关闭连接", sid_for_recv);
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("[Session] {} 读取错误: {}", sid_for_recv, e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    cleanup_session(&session_id, &state).await;
    info!("[Session] {} 已断开 ({})", session_id, addr);
}

/// 直接序列化并发送一条消息到 WebSocket sink
async fn send_msg<S>(sink: &mut S, msg: &ServerMessage) -> Result<(), Box<dyn std::error::Error>>
where
    S: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let bytes = phantom_protocol::serialize(msg)?;
    sink.send(Message::Binary(bytes.into())).await?;
    Ok(())
}

// ============================================================
// 消息处理
// ============================================================

/// 处理一条客户端消息
async fn handle_client_message(session_id: &str, msg: ClientMessage, state: &SharedState) {
    match msg {
        // Ping 和 Auth 不需要认证
        ClientMessage::Ping { client_time_ms } => {
            handle_ping(session_id, client_time_ms, state).await;
        }
        ClientMessage::Auth {
            public_key,
            signature,
            protocol_version,
            client_version,
        } => {
            // 协议不做向后兼容：版本不符直接拒绝并要求升级，
            // 而不是让后续消息以各种诡异的反序列化失败告终。
            if protocol_version != phantom_protocol::PROTOCOL_VERSION {
                warn!(
                    "[鉴权] {} 协议版本不匹配：客户端 {} / 服务端 {} (client_version={})",
                    session_id,
                    protocol_version,
                    phantom_protocol::PROTOCOL_VERSION,
                    client_version
                );
                let st = state.lock().await;
                if let Some(session) = st.sessions.get(session_id) {
                    let _ = session.sender.send(ServerMessage::VersionMismatch {
                        server_protocol_version: phantom_protocol::PROTOCOL_VERSION,
                        client_protocol_version: protocol_version,
                        message: "客户端版本过旧，请升级后再使用".to_string(),
                    });
                }
                return;
            }
            info!(
                "[鉴权] {} 收到 Auth 响应，公钥前4字节: {:?}, 签名长度: {}, 客户端版本: {}",
                session_id,
                &public_key[..4.min(public_key.len())],
                signature.len(),
                client_version
            );
            handle_auth(session_id, public_key, signature, state).await;
        }

        // 以下操作需要认证
        _ => {
            // 鉴权门控（仅在配置启用时检查）
            let auth_enabled = {
                let st = state.lock().await;
                st.config.auth.enabled
            };

            if auth_enabled {
                let st = state.lock().await;
                if let Some(session) = st.sessions.get(session_id) {
                    if !session.authenticated {
                        warn!("[鉴权] {} 未认证，拒绝操作: {:?}", session_id, msg);
                        let _ = session.sender.send(ServerMessage::Error {
                            message: "⏳ 正在认证中，请稍候...".to_string(),
                        });
                        return;
                    }
                } else {
                    return;
                }
            }

            // 已认证，分发消息
            match msg {
                ClientMessage::CreateRoom => {
                    handle_create_room(session_id, state).await;
                }
                ClientMessage::JoinRoom { room_code } => {
                    handle_join_room(session_id, &room_code, state).await;
                }
                ClientMessage::LeaveRoom => {
                    handle_leave_room(session_id, state).await;
                }
                ClientMessage::CloseRoom => {
                    handle_close_room(session_id, state).await;
                }
                ClientMessage::HostReady => {
                    handle_host_ready(session_id, state).await;
                }
                ClientMessage::RelayRequest => {
                    handle_relay_request(session_id, state).await;
                }
                ClientMessage::RelayAssistRequest { loss_bp } => {
                    handle_relay_assist_request(session_id, loss_bp, state).await;
                }
                ClientMessage::RelayAssistRelease => {
                    handle_relay_assist_release(session_id, state).await;
                }
                ClientMessage::RequestFixedHostIp => {
                    handle_request_fixed_host_ip(session_id, state).await;
                }
                ClientMessage::ReleaseFixedHostIp => {
                    handle_release_fixed_host_ip(session_id, state).await;
                }
                ClientMessage::GetFixedHostIp => {
                    handle_get_fixed_host_ip(session_id, state).await;
                }
                ClientMessage::ReportConnectionMode { mode } => {
                    handle_report_connection_mode(session_id, mode, state).await;
                }
                // ── 打洞三阶段 ──────────────────────────────────
                ClientMessage::NatProfileReport {
                    target_peer_session_id,
                    profile,
                    base_candidates,
                } => {
                    handle_nat_profile(
                        session_id,
                        target_peer_session_id,
                        profile,
                        base_candidates,
                        state,
                    )
                    .await;
                }
                ClientMessage::StrategyCandidates {
                    target_peer_session_id,
                    attempt_id,
                    candidates,
                } => {
                    handle_strategy_candidates(
                        session_id,
                        target_peer_session_id,
                        attempt_id,
                        candidates,
                        state,
                    )
                    .await;
                }
                ClientMessage::PunchReport { record } => {
                    handle_punch_report(session_id, record, state).await;
                }
                ClientMessage::RequestLogUpload { reason } => {
                    handle_request_log_upload(session_id, reason, state).await;
                }
                _ => {} // Ping/Auth 已在上面处理
            }
        }
    }
}

/// 处理鉴权响应
async fn handle_auth(
    session_id: &str,
    public_key: [u8; 32],
    signature: [u8; 64],
    state: &SharedState,
) {
    let mut st = state.lock().await;
    // 先克隆配置：下面会持有 sessions 的可变借用，届时无法再读 st.config
    let server_cfg = st.config.clone();
    let session = match st.sessions.get_mut(session_id) {
        Some(s) => s,
        None => return,
    };

    if session.authenticated {
        info!("[鉴权] {} 已认证，忽略重复 Auth", session_id);
        return;
    }

    // 获取 nonce
    let nonce = match session.auth_nonce.take() {
        Some(n) => {
            info!("[鉴权] {} 找到 nonce，长度: {}", session_id, n.len());
            n
        }
        None => {
            warn!("[鉴权] {} 未找到对应的 AuthChallenge nonce", session_id);
            let _ = session.sender.send(ServerMessage::AuthFailed {
                reason: "未找到对应的 AuthChallenge nonce".to_string(),
            });
            return;
        }
    };

    // 验证签名
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(k) => {
            info!("[鉴权] {} 公钥解析成功", session_id);
            k
        }
        Err(e) => {
            warn!("[鉴权] {} 公钥格式无效: {}", session_id, e);
            let _ = session.sender.send(ServerMessage::AuthFailed {
                reason: format!("公钥格式无效: {}", e),
            });
            return;
        }
    };

    let sig = Signature::from_bytes(&signature);

    if verifying_key.verify(&nonce, &sig).is_err() {
        warn!("[鉴权] {} 签名验证失败", session_id);
        let _ = session.sender.send(ServerMessage::AuthFailed {
            reason: "签名验证失败".to_string(),
        });
        return;
    }

    // 验签成功
    let user_id: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    session.authenticated = true;
    session.public_key = Some(public_key);
    session.user_id = Some(user_id.clone());

    // 记录到数据库
    if let Some(db) = database::get_database() {
        let username = format!("用户{}", &user_id[..4]);
        let _ = db.upsert_user(&user_id, &username);
        let _ = db.log_event(&user_id, None, "authenticate", None);
    }

    info!("[鉴权] {} 认证成功 (user_id: {})", session_id, user_id);
    let fixed_host_ip = database::get_database()
        .and_then(|db| db.get_fixed_host_ip(&user_id).ok())
        .flatten();
    let _ = session.sender.send(ServerMessage::AuthOk { user_id });
    let _ = session.sender.send(ServerMessage::FixedHostIpStatus {
        enabled: fixed_host_ip.is_some(),
        virtual_ip: fixed_host_ip,
    });
    // 鉴权后立即下发网络配置——客户端不内置任何 STUN 地址与端口常量，
    // 拿不到这份配置就无法探测 NAT 画像。
    let _ = session.sender.send(ServerMessage::NetworkConfigUpdate {
        config: build_network_config(&server_cfg),
    });
}

/// 组装下发给客户端的网络配置。
///
/// 自建 STUN 排在最前——公共 STUN 不可用时客户端拿不到 srflx 候选，
/// 会直接导致打洞不可能成功而落中继。
fn build_network_config(cfg: &config::ServerConfig) -> phantom_protocol::NetworkConfig {
    let mut stun_servers = Vec::new();
    if cfg.stun.enabled {
        let addr = cfg.stun.effective_addr(&cfg.relay.public_addr);
        stun_servers.push(phantom_protocol::StunServerInfo {
            host: addr.clone(),
            port: cfg.stun.port,
            is_self_hosted: true,
        });
        // 备用端口不是冗余：判定 NAT 映射行为需要至少两个不同的目标端点，
        // 客户端比较两次映射是否一致才能区分锥形与对称。
        stun_servers.push(phantom_protocol::StunServerInfo {
            host: addr,
            port: cfg.stun.alt_port,
            is_self_hosted: true,
        });
    }
    for s in &cfg.stun.fallback_servers {
        if let Some((host, port)) = s.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                stun_servers.push(phantom_protocol::StunServerInfo {
                    host: host.to_string(),
                    port,
                    is_self_hosted: false,
                });
            } else {
                warn!("[配置] 忽略无法解析的 fallback STUN: {}", s);
            }
        }
    }
    phantom_protocol::NetworkConfig {
        stun_servers,
        relay_addr: cfg.relay.public_addr.clone(),
        relay_quic_port: cfg.relay.quic_port,
    }
}

/// 记录客户端上报的最终连接模式（p2p / relay），仅供管理面板只读展示。
/// 接收客户端上报的结构化打洞记录（成功失败都会上报）。
///
/// 这是 NAT 组合成功率分析的唯一数据来源——没有它，
/// 策略参数（撒网宽度、socket 数量、预测深度）只能靠猜。
async fn handle_punch_report(
    session_id: &str,
    record: phantom_protocol::PunchRecord,
    state: &SharedState,
) {
    info!(
        "[打洞遥测] {} attempt={} 策略={} 结果={:?} NAT={:?}→{:?} 建连={}ms 总计={}ms 偏差={}ms",
        session_id,
        record.attempt_id,
        record.strategy.as_str(),
        record.outcome,
        record.local_nat_class,
        record.remote_nat_class,
        record.p2p_establish_ms,
        record.total_ms,
        record.punch_start_skew_ms
    );

    let user_id = {
        let st = state.lock().await;
        st.sessions
            .get(session_id)
            .and_then(|s| s.user_id.clone())
            .unwrap_or_else(|| session_id.to_string())
    };

    if let Some(db) = database::get_database() {
        if let Err(e) = db.insert_punch_record(&user_id, &record) {
            warn!("[打洞遥测] 落库失败: {}", e);
        }
    }
}

/// 签发一次性日志上传凭据。
///
/// 用户主动"反馈问题"时触发。凭据绑定 user_id 并有过期时间——
/// 这样落盘时能按用户归类，也不必信任客户端自报的身份。
async fn handle_request_log_upload(session_id: &str, reason: String, state: &SharedState) {
    let (sender, user_id, registry) = {
        let st = state.lock().await;
        let Some(session) = st.sessions.get(session_id) else {
            return;
        };
        (
            session.sender.clone(),
            session.user_id.clone(),
            st.log_uploads.clone(),
        )
    };

    let Some(registry) = registry else {
        let _ = sender.send(ServerMessage::Error {
            message: "服务端未启用日志上报".to_string(),
        });
        return;
    };
    // 未鉴权用户不签发：否则无法归类，也会成为磁盘灌满的入口
    let Some(user_id) = user_id else {
        let _ = sender.send(ServerMessage::Error {
            message: "需要先完成鉴权才能上报日志".to_string(),
        });
        return;
    };

    let url = registry.issue(&user_id, &reason).await;
    info!(
        "[日志上报] 已为 {} 签发上传凭据 (原因: {})",
        user_id, reason
    );
    let _ = sender.send(ServerMessage::RequestLogUpload {
        upload_url: url,
        reason,
    });
}

/// 上报最终连接模式。
///
/// **P2P 成功时必须释放预分配的中继槽位。**
/// 旧实现只记了个字段，导致中继消耗量等于房间总数而非失败房间数——
/// 这是中继资源被打爆的直接原因，与打洞成功率无关。
async fn handle_report_connection_mode(session_id: &str, mode: String, state: &SharedState) {
    let release_target = {
        let mut st = state.lock().await;
        let Some(session) = st.sessions.get_mut(session_id) else {
            return;
        };
        info!("[连接模式] {} 上报: {}", session_id, mode);
        session.connection_mode = Some(mode.clone());
        let room_code = session.room_code.clone();

        if mode != "p2p" {
            None
        } else {
            // 仅当该房间所有在场成员都已上报 p2p 时才释放：
            // 多人房间里只要还有一个人走中继，槽位就不能回收。
            room_code.and_then(|code| {
                let room = st.rooms.get(&code)?;
                let token = match &room.state {
                    RoomState::Relaying { token, .. } => token.clone(),
                    _ => return None,
                };
                let mut members = vec![room.host_session_id.clone()];
                members.extend(room.guests.iter().cloned());
                let all_p2p = members.iter().all(|sid| {
                    st.sessions
                        .get(sid)
                        .map(|s| s.connection_mode.as_deref() == Some("p2p"))
                        .unwrap_or(false)
                });
                if all_p2p {
                    Some((code, token))
                } else {
                    None
                }
            })
        }
    };

    if let Some((room_code, token)) = release_target {
        let registry = {
            let st = state.lock().await;
            st.relay_registry.clone()
        };
        registry.lock().await.consume_token(&token).await;
        let mut st = state.lock().await;
        if let Some(room) = st.rooms.get_mut(&room_code) {
            // 房间仍然存活，只是不再占用中继资源
            room.state = RoomState::WaitingGuest;
        }
        info!(
            "[中继回收] 房间 {} 全员 P2P 直连，已释放中继槽位 (token={})",
            room_code, token
        );
    }
}

async fn handle_get_fixed_host_ip(session_id: &str, state: &SharedState) {
    let st = state.lock().await;
    let Some(session) = st.sessions.get(session_id) else {
        return;
    };
    let Some(user_id) = session.user_id.as_deref() else {
        let _ = session.sender.send(ServerMessage::Error {
            message: "Authentication is required for a fixed Host IP".to_string(),
        });
        return;
    };
    let virtual_ip = database::get_database()
        .and_then(|db| db.get_fixed_host_ip(user_id).ok())
        .flatten();
    let _ = session.sender.send(ServerMessage::FixedHostIpStatus {
        enabled: virtual_ip.is_some(),
        virtual_ip,
    });
}

async fn handle_request_fixed_host_ip(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    let Some(session) = st.sessions.get(session_id) else {
        return;
    };
    let Some(user_id) = session.user_id.clone() else {
        let _ = session.sender.send(ServerMessage::Error {
            message: "Authentication is required for a fixed Host IP".to_string(),
        });
        return;
    };
    let Some(db) = database::get_database() else {
        let _ = session.sender.send(ServerMessage::Error {
            message: "Fixed Host IP database is unavailable".to_string(),
        });
        return;
    };
    match db.allocate_fixed_host_ip(&user_id) {
        Ok(virtual_ip) => {
            let _ = db.log_event(&user_id, None, "allocate_fixed_host_ip", Some(&virtual_ip));
            info!("[fixed-ip] user {} allocated {}", user_id, virtual_ip);
            if let Err(error) = hot_reconfigure_host_ip(&mut st, session_id, &virtual_ip, &db) {
                if let Some(session) = st.sessions.get(session_id) {
                    let _ = session.sender.send(ServerMessage::Error { message: error });
                }
                return;
            }
            if let Some(session) = st.sessions.get(session_id) {
                let _ = session.sender.send(ServerMessage::FixedHostIpStatus {
                    enabled: true,
                    virtual_ip: Some(virtual_ip),
                });
            }
        }
        Err(error) => {
            error!("[fixed-ip] allocation failed for {}: {}", user_id, error);
            let _ = session.sender.send(ServerMessage::Error {
                message: "No fixed Host IP is currently available".to_string(),
            });
        }
    }
}

async fn handle_release_fixed_host_ip(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    let (user_id, room_code, sender) = match st.sessions.get(session_id) {
        Some(session) => match (session.user_id.clone(), session.room_code.clone()) {
            (Some(user_id), room_code) => (user_id, room_code, session.sender.clone()),
            (None, _) => {
                let _ = session.sender.send(ServerMessage::Error {
                    message: "Authentication is required for a fixed Host IP".to_string(),
                });
                return;
            }
        },
        None => return,
    };
    let Some(db) = database::get_database() else {
        let _ = sender.send(ServerMessage::Error {
            message: "Fixed Host IP database is unavailable".to_string(),
        });
        return;
    };
    let dynamic_ip = room_code
        .as_ref()
        .and_then(|code| st.rooms.get(code).map(|room| format!("{}.1", room.subnet)));
    if let Some(dynamic_ip) = dynamic_ip.as_deref() {
        if let Err(error) = hot_reconfigure_host_ip(&mut st, session_id, dynamic_ip, &db) {
            if let Some(session) = st.sessions.get(session_id) {
                let _ = session.sender.send(ServerMessage::Error { message: error });
            }
            return;
        }
    }
    match db.release_fixed_host_ip(&user_id) {
        Ok(released) => {
            if let Some(ip) = released.as_deref() {
                let _ = db.log_event(&user_id, None, "release_fixed_host_ip", Some(ip));
                info!("[fixed-ip] user {} released {}", user_id, ip);
            }
            let _ = sender.send(ServerMessage::FixedHostIpStatus {
                enabled: false,
                virtual_ip: None,
            });
        }
        Err(error) => {
            error!("[fixed-ip] release failed for {}: {}", user_id, error);
            let _ = sender.send(ServerMessage::Error {
                message: "Failed to release the fixed Host IP".to_string(),
            });
        }
    }
}

fn hot_reconfigure_host_ip(
    st: &mut AppState,
    session_id: &str,
    new_host_ip: &str,
    db: &database::Database,
) -> Result<(), String> {
    let Some(room_code) = st
        .sessions
        .get(session_id)
        .and_then(|session| session.room_code.clone())
    else {
        return Ok(());
    };
    if !matches!(
        st.sessions.get(session_id).and_then(|s| s.role.as_ref()),
        Some(Role::Host)
    ) {
        return Err("Only a Host can change the active room address".to_string());
    }
    db.assign_peer_ip(&room_code, session_id, new_host_ip, "host")
        .map_err(|error| format!("Failed to update the active Host address: {error}"))?;

    let (subnet, guests) = {
        let room = st
            .rooms
            .get_mut(&room_code)
            .ok_or_else(|| "The active room no longer exists".to_string())?;
        room.host_virtual_ip = new_host_ip.to_string();
        room.state = RoomState::Created;
        // Host 地址变了，之前所有打洞会话的候选全部作废
        room.punch_sessions.clear();
        (
            room.subnet.clone(),
            room.guests.iter().cloned().collect::<Vec<_>>(),
        )
    };
    if let Some(host) = st.sessions.get_mut(session_id) {
        host.virtual_ip = Some(new_host_ip.to_string());
        let _ = host.sender.send(ServerMessage::RoomCreated {
            room_code: room_code.clone(),
            subnet: subnet.clone(),
            virtual_ip: new_host_ip.to_string(),
        });
        for (index, guest_id) in guests.iter().enumerate() {
            let _ = host.sender.send(ServerMessage::PeerJoined {
                peer_session_id: guest_id.clone(),
                guest_count: index + 1,
            });
        }
    }
    for guest_id in guests {
        if let Some(guest) = st.sessions.get(&guest_id) {
            if let Some(virtual_ip) = guest.virtual_ip.clone() {
                let _ = guest.sender.send(ServerMessage::JoinOk {
                    room_code: room_code.clone(),
                    host_session_id: session_id.to_string(),
                    subnet: subnet.clone(),
                    virtual_ip,
                    host_virtual_ip: new_host_ip.to_string(),
                });
            }
        }
    }
    info!(
        "[fixed-ip] room {} retained its code and switched Host address to {}",
        room_code, new_host_ip
    );
    Ok(())
}

/// 为房间登记一个中继 token。
///
/// 不再分配端口——所有房间共用启动时就绪的那一个 QUIC 监听端口，
/// 房间路由完全靠首流里的 token。原先的"分配端口 → 起监听 → 失败重试"
/// 那一整套逻辑随之消失，容量上限也不再由端口数决定。
async fn allocate_relay_slot(
    state: &SharedState,
    relay_registry: &relay::SharedRegistry,
    room_code: &str,
) -> Result<(String, u16), String> {
    let quic_port = {
        let st = state.lock().await;
        st.config.relay.quic_port
    };
    let token = Uuid::new_v4().to_string();
    relay_registry.lock().await.register_token(token.clone());
    info!(
        "[中继] 房间 {} 登记 token（共用端口 {}）",
        room_code, quic_port
    );
    Ok((token, quic_port))
}

async fn guest_relay_credential(registry: &relay::SharedRegistry, room_token: &str) -> String {
    let credential = Uuid::new_v4().to_string();
    registry
        .lock()
        .await
        .register_guest_credential(room_token, credential.clone());
    credential
}

/// 计算双方各自的**起跑等待时长**。
///
/// 返回 `(host 等待毫秒, guest 等待毫秒)`。
///
/// 不下发绝对时间戳：那要求两端与服务端的墙钟一致，而客户端时钟偏差会
/// **等量地破坏同步**——实测偏差达 3.5 秒，比同步窗口本身还大。
///
/// 改成"收到后再等 N 毫秒"，并为每端减去**它自己的**单程延迟（RTT/2）：
/// 消息晚到的一方等得少，早到的一方等得多，两端实际起跑时刻因而对齐，
/// 且完全不依赖任何一方的时钟。
fn compute_start_delays(host_rtt_ms: u32, guest_rtt_ms: u32) -> (u32, u32) {
    const MIN_LEAD_MS: u32 = 500;
    const MAX_LEAD_MS: u32 = 3_000;
    // 统一的目标提前量按较慢一方决定，保证两端都来得及
    let worst = host_rtt_ms.max(guest_rtt_ms);
    let lead = (worst * 3 / 2 + 200).clamp(MIN_LEAD_MS, MAX_LEAD_MS);
    // 各自扣掉自己的单程延迟；saturating_sub 保证不会因 RTT 异常大而下溢
    (
        lead.saturating_sub(host_rtt_ms / 2),
        lead.saturating_sub(guest_rtt_ms / 2),
    )
}

/// **阶段一**：收到一端的 NAT 画像与基础候选。
///
/// 双方都到齐后计算策略并下发 [`ServerMessage::PunchPlan`]；
/// 若双方都不需要新建 socket（快速通道），紧接着直接下发 PunchStart。
async fn handle_nat_profile(
    session_id: &str,
    target_peer_session_id: Option<String>,
    profile: phantom_protocol::NatProfile,
    base_candidates: Vec<phantom_protocol::IceCandidate>,
    state: &SharedState,
) {
    let Some((room_code, guest_sid, is_host)) =
        resolve_punch_pair(session_id, target_peer_session_id.as_deref(), state).await
    else {
        return;
    };

    info!(
        "[打洞] {} 上报 NAT 画像: class={:?} detail={} base_port={} step={} ipv6={} 候选={} 个",
        session_id,
        profile.class,
        profile.detail,
        profile.base_port,
        profile.step,
        profile.has_ipv6,
        base_candidates.len()
    );

    {
        let mut st = state.lock().await;
        let Some(room) = st.rooms.get_mut(&room_code) else {
            return;
        };
        let sess = room
            .punch_sessions
            .entry(guest_sid.clone())
            .or_insert_with(PunchSession::new);
        // 同一端重新上报画像视为重新发起一轮，重置该轮状态
        if sess.started {
            *sess = PunchSession::new();
        }
        let side = sess.side_mut(is_host);
        side.profile = Some(profile);
        side.base_candidates = base_candidates;
        side.strategy_candidates.clear();
        side.strategy_reported = false;
    }

    try_advance_punch(&room_code, &guest_sid, state).await;
    spawn_relay_preallocation(&room_code, state).await;
}

/// **阶段二**：收到一端按策略生成的候选（新建 socket 的映射等）
async fn handle_strategy_candidates(
    session_id: &str,
    target_peer_session_id: String,
    attempt_id: String,
    candidates: Vec<phantom_protocol::IceCandidate>,
    state: &SharedState,
) {
    let Some((room_code, guest_sid, is_host)) =
        resolve_punch_pair(session_id, Some(&target_peer_session_id), state).await
    else {
        return;
    };

    {
        let mut st = state.lock().await;
        let Some(room) = st.rooms.get_mut(&room_code) else {
            return;
        };
        let Some(sess) = room.punch_sessions.get_mut(&guest_sid) else {
            warn!("[打洞] {} 上报策略候选，但会话不存在，丢弃", session_id);
            return;
        };
        // attempt_id 不匹配说明是上一轮的迟到消息，丢弃以免污染本轮
        if sess.attempt_id != attempt_id {
            warn!(
                "[打洞] {} 的策略候选 attempt_id 过期（{} != {}），丢弃",
                session_id, attempt_id, sess.attempt_id
            );
            return;
        }
        info!(
            "[打洞] {} 上报 {} 个策略候选 (attempt={})",
            session_id,
            candidates.len(),
            attempt_id
        );
        let side = sess.side_mut(is_host);
        side.strategy_candidates = candidates;
        side.strategy_reported = true;
    }

    try_advance_punch(&room_code, &guest_sid, state).await;
}

/// 定位本次上报属于哪个房间的哪一对 Host↔Guest。
///
/// 返回 `(room_code, guest_session_id, 本端是否为 Host)`。
async fn resolve_punch_pair(
    session_id: &str,
    target_peer_session_id: Option<&str>,
    state: &SharedState,
) -> Option<(String, String, bool)> {
    let st = state.lock().await;
    let session = st.sessions.get(session_id)?;
    let room_code = match &session.room_code {
        Some(c) => c.clone(),
        None => {
            let _ = session.sender.send(ServerMessage::Error {
                message: "你不在房间中".to_string(),
            });
            return None;
        }
    };
    let room = st.rooms.get(&room_code)?;
    let is_host = session_id == room.host_session_id;
    let guest_sid = if is_host {
        // Host 必须指明是对哪个 Guest，否则无法区分多人场景
        let target = target_peer_session_id?;
        if !room.guests.contains(target) {
            return None;
        }
        target.to_string()
    } else {
        session_id.to_string()
    };
    Some((room_code, guest_sid, is_host))
}

/// 推进打洞状态机：够条件就下发 PunchPlan / PunchStart。
async fn try_advance_punch(room_code: &str, guest_sid: &str, state: &SharedState) {
    // ── 阶段一 → 下发 PunchPlan ────────────────────────────────
    let plan = {
        let mut st = state.lock().await;
        let Some(room) = st.rooms.get_mut(room_code) else {
            return;
        };
        let host_sid = room.host_session_id.clone();
        let Some(sess) = room.punch_sessions.get_mut(guest_sid) else {
            return;
        };

        match (&sess.host.profile, &sess.guest.profile) {
            (Some(h), Some(g)) if !sess.plan_sent => {
                let ipv6_both = h.has_ipv6 && g.has_ipv6;
                let same_public_ip = match (&h.public_ip, &g.public_ip) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                let host_strategy = phantom_protocol::PunchStrategy::select(
                    h.class,
                    g.class,
                    ipv6_both,
                    same_public_ip,
                );
                let guest_strategy = phantom_protocol::PunchStrategy::select(
                    g.class,
                    h.class,
                    ipv6_both,
                    same_public_ip,
                );
                let host_params = phantom_protocol::PunchParams::for_strategy(host_strategy);
                let guest_params = phantom_protocol::PunchParams::for_strategy(guest_strategy);

                sess.host.needs_strategy = host_strategy.needs_strategy_candidates();
                sess.guest.needs_strategy = guest_strategy.needs_strategy_candidates();
                sess.plan_sent = true;

                Some((
                    host_sid,
                    sess.attempt_id.clone(),
                    host_strategy,
                    host_params,
                    h.clone(),
                    sess.host.needs_strategy,
                    guest_strategy,
                    guest_params,
                    g.clone(),
                    sess.guest.needs_strategy,
                ))
            }
            _ => None,
        }
    };

    if let Some((
        host_sid,
        attempt_id,
        host_strategy,
        host_params,
        host_profile,
        host_needs,
        guest_strategy,
        guest_params,
        guest_profile,
        guest_needs,
    )) = plan
    {
        info!(
            "[打洞] 房间 {} 配对 {}↔{}: 策略 host={} guest={} (attempt={})",
            room_code,
            host_sid,
            guest_sid,
            host_strategy.as_str(),
            guest_strategy.as_str(),
            attempt_id
        );
        let st = state.lock().await;
        if let Some(s) = st.sessions.get(&host_sid) {
            let _ = s.sender.send(ServerMessage::PunchPlan {
                peer_session_id: guest_sid.to_string(),
                attempt_id: attempt_id.clone(),
                strategy: host_strategy,
                params: host_params,
                // 下发给 Host 的是 Guest 的画像
                peer_profile: guest_profile,
                needs_strategy_candidates: host_needs,
            });
        }
        if let Some(s) = st.sessions.get(guest_sid) {
            let _ = s.sender.send(ServerMessage::PunchPlan {
                peer_session_id: host_sid.clone(),
                attempt_id,
                strategy: guest_strategy,
                params: guest_params,
                peer_profile: host_profile,
                needs_strategy_candidates: guest_needs,
            });
        }
    }

    // ── 阶段三 → 双方候选集齐后下发 PunchStart ──────────────────
    let start = {
        let mut st = state.lock().await;
        let Some(room) = st.rooms.get_mut(room_code) else {
            return;
        };
        let host_sid = room.host_session_id.clone();
        let Some(sess) = room.punch_sessions.get_mut(guest_sid) else {
            return;
        };
        if sess.started || !sess.host.ready_for_start() || !sess.guest.ready_for_start() {
            None
        } else {
            sess.started = true;
            let host_rtt = sess.host.profile.as_ref().map_or(0, |p| p.signal_rtt_ms);
            let guest_rtt = sess.guest.profile.as_ref().map_or(0, |p| p.signal_rtt_ms);
            Some((
                host_sid,
                sess.attempt_id.clone(),
                sess.host.all_candidates(),
                sess.guest.all_candidates(),
                compute_start_delays(host_rtt, guest_rtt),
            ))
        }
    };

    if let Some((host_sid, attempt_id, host_cands, guest_cands, (host_delay, guest_delay))) = start
    {
        info!(
            "[打洞] 房间 {} 配对 {}↔{} 同步启动: 等待 host={}ms guest={}ms, host候选={} guest候选={}",
            room_code,
            host_sid,
            guest_sid,
            host_delay,
            guest_delay,
            host_cands.len(),
            guest_cands.len()
        );
        let st = state.lock().await;
        if let Some(s) = st.sessions.get(&host_sid) {
            let _ = s.sender.send(ServerMessage::PunchStart {
                peer_session_id: guest_sid.to_string(),
                attempt_id: attempt_id.clone(),
                peer_candidates: guest_cands,
                start_delay_ms: host_delay,
            });
        }
        if let Some(s) = st.sessions.get(guest_sid) {
            let _ = s.sender.send(ServerMessage::PunchStart {
                peer_session_id: host_sid.clone(),
                attempt_id,
                peer_candidates: host_cands,
                start_delay_ms: guest_delay,
            });
        }
    }
}

/// 后台预分配中继（不阻塞打洞流程）。
///
/// 预分配本身是合理的加速手段——省掉打洞失败后再申请的往返。
/// 但**必须配合回收**：见 [`handle_report_connection_mode`]，
/// 客户端上报 `"p2p"` 时释放槽位，否则中继消耗量会等于房间总数。
async fn spawn_relay_preallocation(room_code: &str, state: &SharedState) {
    let (relay_addr, relay_registry) = {
        let st = state.lock().await;
        (
            st.config.relay.public_addr.clone(),
            st.relay_registry.clone(),
        )
    };
    let state_clone = state.clone();
    let room_code_clone = room_code.to_string();
    tokio::spawn(async move {
        // 检查是否已有有效中继分配
        let already_allocated = {
            let st = state_clone.lock().await;
            if let Some(room) = st.rooms.get(&room_code_clone) {
                if let RoomState::Relaying { token, .. } = &room.state {
                    let reg = st.relay_registry.lock().await;
                    reg.is_valid(token)
                } else {
                    false
                }
            } else {
                false
            }
        };

        if already_allocated {
            // 已有中继，向所有人重新下发 RelayPreAllocated
            let st = state_clone.lock().await;
            if let Some(room) = st.rooms.get(&room_code_clone) {
                if let RoomState::Relaying { token, quic_port } = &room.state {
                    let token = token.clone();
                    let quic_port = *quic_port;
                    let relay = relay_addr.clone();
                    let mut all_ids = vec![room.host_session_id.clone()];
                    all_ids.extend(room.guests.iter().cloned());
                    for sid in all_ids {
                        if let Some(sess) = st.sessions.get(&sid) {
                            let credential = if matches!(sess.role, Some(Role::Host)) {
                                token.clone()
                            } else {
                                guest_relay_credential(&relay_registry, &token).await
                            };
                            let _ = sess.sender.send(ServerMessage::RelayPreAllocated {
                                room_code: room_code_clone.clone(),
                                relay_addr: relay.clone(),
                                relay_quic_port: quic_port,
                                token: credential,
                            });
                        }
                    }
                }
            }
            return;
        }

        match allocate_relay_slot(&state_clone, &relay_registry, &room_code_clone).await {
            Ok((token, quic_port)) => {
                let mut st = state_clone.lock().await;
                if let Some(room) = st.rooms.get_mut(&room_code_clone) {
                    room.state = RoomState::Relaying {
                        token: token.clone(),
                        quic_port,
                    };
                    let mut all_ids = vec![room.host_session_id.clone()];
                    all_ids.extend(room.guests.iter().cloned());
                    for sid in all_ids {
                        if let Some(sess) = st.sessions.get(&sid) {
                            let credential = if matches!(sess.role, Some(Role::Host)) {
                                token.clone()
                            } else {
                                guest_relay_credential(&relay_registry, &token).await
                            };
                            let _ = sess.sender.send(ServerMessage::RelayPreAllocated {
                                room_code: room_code_clone.clone(),
                                relay_addr: relay_addr.clone(),
                                relay_quic_port: quic_port,
                                token: credential,
                            });
                        }
                    }
                }
                info!(
                    "[ICE-预分配] 房间 {} 中继预分配成功，quic_port={}",
                    room_code_clone, quic_port
                );
            }
            Err(e) => {
                warn!(
                    "[ICE-预分配] 房间 {} 中继预分配失败: {}",
                    room_code_clone, e
                );
            }
        }
    });
}

/// 处理中继请求 — 生成 token 并向房间内双方下发同一个 RelayReady
/// 处理「借用中继补包」的求援。
///
/// 与整体切中继不同，这里只放行**补包**流量：原包继续走 P2P，中继只承担
/// 丢掉的那一小部分。同样丢包程度下中继带宽占用低数倍，所以同一条 50Mbps
/// 中继能同时照顾的房间数高得多。
///
/// 带宽是硬约束，因此用并发授权数封顶；排满就直接拒绝，
/// 客户端会退回纯 P2P 补包。宁可让一个房间体验差一点，
/// 也不能让所有房间一起被拖垮。
async fn handle_relay_assist_request(session_id: &str, loss_bp: u16, state: &SharedState) {
    let mut st = state.lock().await;
    let (room_code, sender) = match st.sessions.get(session_id) {
        Some(s) => match &s.room_code {
            Some(code) => (code.clone(), s.sender.clone()),
            None => return,
        },
        None => return,
    };

    let cap = st.config.relay.max_assist_rooms;
    let already = st.relay_assist_rooms.contains(&room_code);
    if !already && st.relay_assist_rooms.len() >= cap {
        warn!(
            "[中继补包] 房间 {} 求援被拒：已有 {} 个房间在用，达到上限 {}",
            room_code,
            st.relay_assist_rooms.len(),
            cap
        );
        let _ = sender.send(ServerMessage::RelayAssistDenied {
            reason: "中继带宽已满，请稍后重试".to_string(),
        });
        return;
    }

    // 复用房间既有的中继 token；没有就现签一个
    let token = match st.rooms.get(&room_code).map(|r| &r.state) {
        Some(RoomState::Relaying { token, .. }) => token.clone(),
        _ => {
            let token = format!("assist-{}-{}", room_code, session_id);
            let registry = st.relay_registry.clone();
            let mut reg = registry.lock().await;
            reg.register_token(token.clone());
            token
        }
    };

    st.relay_assist_rooms.insert(room_code.clone());
    let addr = st.config.relay.public_addr.clone();
    let port = st.config.relay.quic_port;
    info!(
        "[中继补包] 房间 {} 获准借用中继（丢包 {:.2}%，当前 {}/{}）",
        room_code,
        loss_bp as f64 / 100.0,
        st.relay_assist_rooms.len(),
        cap
    );
    let _ = sender.send(ServerMessage::RelayAssistGranted {
        relay_addr: addr,
        relay_quic_port: port,
        token,
    });
}

/// 链路恢复后客户端主动交还额度，把带宽让给别的房间
async fn handle_relay_assist_release(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    let Some(room_code) = st
        .sessions
        .get(session_id)
        .and_then(|s| s.room_code.clone())
    else {
        return;
    };
    if st.relay_assist_rooms.remove(&room_code) {
        info!(
            "[中继补包] 房间 {} 交还额度，当前 {}/{}",
            room_code,
            st.relay_assist_rooms.len(),
            st.config.relay.max_assist_rooms
        );
    }
}

async fn handle_relay_request(session_id: &str, state: &SharedState) {
    let (room_code, relay_addr, relay_registry, requester_sender, existing_ready, requester_role) = {
        let st = state.lock().await;
        let session = match st.sessions.get(session_id) {
            Some(s) => s,
            None => return,
        };

        let (room_code, requester_role) = match (&session.room_code, &session.role) {
            (Some(code), Some(role)) => (code.clone(), role.clone()),
            _ => {
                let _ = session.sender.send(ServerMessage::Error {
                    message: "你不在房间中，无法请求中继".to_string(),
                });
                return;
            }
        };

        let existing_ready = if let Some(room) = st.rooms.get(&room_code) {
            if let RoomState::Relaying { token, quic_port } = &room.state {
                Some((token.clone(), *quic_port))
            } else {
                None
            }
        } else {
            let _ = session.sender.send(ServerMessage::Error {
                message: "房间不存在，无法请求中继".to_string(),
            });
            return;
        };

        (
            room_code,
            st.config.relay.public_addr.clone(),
            st.relay_registry.clone(),
            session.sender.clone(),
            existing_ready,
            requester_role,
        )
    };

    // 房间已经在中继，先校验 token 是否仍有效，避免复用过期 token
    if let Some((token, quic_port)) = existing_ready {
        let token_valid = {
            let reg = relay_registry.lock().await;
            reg.is_valid(&token)
        };
        if token_valid {
            let credential = match &requester_role {
                Role::Host => token.clone(),
                Role::Guest => guest_relay_credential(&relay_registry, &token).await,
            };
            let _ = requester_sender.send(ServerMessage::RelayReady {
                room_code: room_code.clone(),
                relay_addr,
                relay_quic_port: quic_port,
                token: credential,
            });
            return;
        }

        warn!(
            "[中继] 房间 {} 发现过期 token，重置中继状态并重新分配",
            room_code
        );

        {
            let mut reg = relay_registry.lock().await;
            reg.consume_token(&token).await;
        }

        let mut st = state.lock().await;
        if let Some(room) = st.rooms.get_mut(&room_code) {
            if let RoomState::Relaying {
                token: current_token,
                ..
            } = &room.state
            {
                if *current_token == token {
                    room.state = if room.guests.is_empty() {
                        RoomState::WaitingGuest
                    } else {
                        RoomState::Created
                    };
                }
            }
        }
    }

    let (token, quic_port) = match allocate_relay_slot(state, &relay_registry, &room_code).await {
        Ok(slot) => slot,
        Err(msg) => {
            let _ = requester_sender.send(ServerMessage::Error { message: msg });
            return;
        }
    };

    let mut st = state.lock().await;
    let participants = if let Some(room) = st.rooms.get_mut(&room_code) {
        // 避免并发重复分配：如果已有中继状态，复用并回收本次新 token
        if let RoomState::Relaying {
            token: existing_token,
            quic_port: existing_quic,
        } = &room.state
        {
            let existing_token = existing_token.clone();
            let existing_quic = *existing_quic;
            let relay_registry_clone = relay_registry.clone();
            tokio::spawn(async move {
                let mut reg = relay_registry_clone.lock().await;
                reg.consume_token(&token).await;
            });
            let credential = match &requester_role {
                Role::Host => existing_token.clone(),
                Role::Guest => guest_relay_credential(&relay_registry, &existing_token).await,
            };
            let _ = requester_sender.send(ServerMessage::RelayReady {
                room_code: room_code.clone(),
                relay_addr,
                relay_quic_port: existing_quic,
                token: credential,
            });
            return;
        }

        room.state = RoomState::Relaying {
            token: token.clone(),
            quic_port,
        };

        let mut ids = Vec::with_capacity(room.guests.len() + 1);
        ids.push(room.host_session_id.clone());
        ids.extend(room.guests.iter().cloned());
        ids
    } else {
        let relay_registry_clone = relay_registry.clone();
        tokio::spawn(async move {
            let mut reg = relay_registry_clone.lock().await;
            reg.consume_token(&token).await;
        });
        let _ = requester_sender.send(ServerMessage::Error {
            message: "房间已关闭，无法分配中继".to_string(),
        });
        return;
    };

    info!(
        "[中继] 房间 {} 统一分配 token:{} QUIC:{}",
        room_code, token, quic_port
    );

    for sid in participants {
        if let Some(session) = st.sessions.get(&sid) {
            let credential = if matches!(session.role, Some(Role::Host)) {
                token.clone()
            } else {
                guest_relay_credential(&relay_registry, &token).await
            };
            let _ = session.sender.send(ServerMessage::RelayReady {
                room_code: room_code.clone(),
                relay_addr: relay_addr.clone(),
                relay_quic_port: quic_port,
                token: credential,
            });
        }
    }
}

/// 处理 Ping
///
/// 回显客户端时间戳，使客户端能只用本机时钟测出信令 RTT
/// （不依赖两端时钟同步）。该 RTT 随 NatProfile 上报回服务端，
/// 用于计算打洞的自适应同步窗口。
async fn handle_ping(session_id: &str, client_time_ms: u64, state: &SharedState) {
    let mut st = state.lock().await;
    if let Some(session) = st.sessions.get_mut(session_id) {
        // 更新最后活动时间
        session.last_activity = tokio::time::Instant::now();
        let _ = session.sender.send(ServerMessage::Pong {
            client_time_ms,
            server_time_ms: now_ms(),
        });
    }
}

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 处理创建房间
async fn handle_create_room(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;

    // 检查是否已在房间中
    let (session_addr, owner_id) = if let Some(session) = st.sessions.get(session_id) {
        if session.room_code.is_some() {
            let _ = session.sender.send(ServerMessage::Error {
                message: "你已经在一个房间中，请先离开当前房间".to_string(),
            });
            return;
        }
        (session.addr, session.user_id.clone())
    } else {
        return; // session 不存在
    };

    // 速率限制：单 IP 每分钟最多创建 5 个房间
    let ip_str = session_addr.ip().to_string();
    let now = std::time::Instant::now();
    let (count, last_reset) = st
        .rate_limit_create
        .entry(ip_str.clone())
        .or_insert((0, now));

    // 如果超过 1 分钟，重置计数
    if now.duration_since(*last_reset) > std::time::Duration::from_secs(60) {
        *count = 0;
        *last_reset = now;
    }

    if *count >= 5 {
        warn!("[速率限制] {} 创建房间过于频繁", session_addr);
        if let Some(session) = st.sessions.get(session_id) {
            let _ = session.sender.send(ServerMessage::Error {
                message: "创建房间过于频繁，请稍后再试".to_string(),
            });
        }
        return;
    }
    *count += 1;

    // 生成配对码
    let code = st.generate_room_code();
    let Some(db) = database::get_database() else {
        return;
    };
    let subnet = match db.allocate_subnet(&code) {
        Ok(subnet) => subnet,
        Err(error) => {
            error!("[room] failed to allocate dynamic Guest subnet: {}", error);
            if let Some(session) = st.sessions.get(session_id) {
                let _ = session.sender.send(ServerMessage::Error {
                    message: "No dynamic room subnet is currently available".to_string(),
                });
            }
            return;
        }
    };
    let fixed_host_ip = match owner_id.as_deref() {
        Some(user_id) => match db.get_fixed_host_ip(user_id) {
            Ok(ip) => ip,
            Err(error) => {
                error!(
                    "[room] failed to read fixed Host IP for {}: {}",
                    user_id, error
                );
                let _ = db.release_room_network(&code);
                return;
            }
        },
        None => None,
    };
    let host_virtual_ip = fixed_host_ip.unwrap_or_else(|| format!("{}.1", subnet));
    if let Err(error) = db.assign_peer_ip(&code, session_id, &host_virtual_ip, "host") {
        error!(
            "[room] failed to assign Host virtual IP {}: {}",
            host_virtual_ip, error
        );
        let _ = db.release_room_network(&code);
        if let Some(session) = st.sessions.get(session_id) {
            let _ = session.sender.send(ServerMessage::Error {
                message: "Failed to assign the Host virtual IP".to_string(),
            });
        }
        return;
    }

    // 创建房间
    let room = Room {
        code: code.clone(),
        host_session_id: session_id.to_string(),
        subnet: subnet.clone(),
        host_virtual_ip: host_virtual_ip.clone(),
        guests: HashSet::new(),
        created_at: std::time::Instant::now(),
        state: RoomState::Created,
        punch_sessions: HashMap::new(),
    };
    st.rooms.insert(code.clone(), room);

    // 记录到数据库
    if let Some(session) = st.sessions.get(session_id) {
        let owner_id = session.user_id.as_deref().unwrap_or(session_id);
        let _ = db.create_room(&code, owner_id);
        let _ = db.log_event(owner_id, Some(&code), "create_room", Some(&host_virtual_ip));
    }

    // 更新 session 状态
    if let Some(session) = st.sessions.get_mut(session_id) {
        session.room_code = Some(code.clone());
        session.role = Some(Role::Host);
        session.virtual_ip = Some(host_virtual_ip.clone());
        let _ = session.sender.send(ServerMessage::RoomCreated {
            room_code: code.clone(),
            subnet: subnet.clone(),
            virtual_ip: host_virtual_ip.clone(),
        });
    }

    info!(
        "[房间] {} 创建了房间 {} (子网: {})",
        session_id, code, subnet,
    );
}

/// 处理加入房间
async fn handle_host_ready(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    let room_code = match st.sessions.get(session_id) {
        Some(session) if matches!(session.role, Some(Role::Host)) => session.room_code.clone(),
        _ => None,
    };
    let Some(room_code) = room_code else {
        return;
    };

    if let Some(room) = st.rooms.get_mut(&room_code) {
        if matches!(room.state, RoomState::Created) {
            room.state = RoomState::WaitingGuest;
            info!(
                "Host {} TUN ready; room {} is now open",
                session_id, room_code
            );
        }
    }
}

async fn handle_join_room(session_id: &str, room_code: &str, state: &SharedState) {
    let mut st = state.lock().await;

    // 检查是否已在房间中
    if let Some(session) = st.sessions.get(session_id) {
        if session.room_code.is_some() {
            let _ = session.sender.send(ServerMessage::Error {
                message: "你已经在一个房间中，请先离开当前房间".to_string(),
            });
            return;
        }
    } else {
        return;
    }

    // 标准化配对码（转大写、去空格）
    let code = room_code.trim().to_uppercase();

    // 查找房间并获取 subnet
    let guest_virtual_ip = {
        let room = match st.rooms.get(&code) {
            Some(room) => room,
            None => {
                if let Some(session) = st.sessions.get(session_id) {
                    let _ = session.sender.send(ServerMessage::JoinFailed {
                        reason: format!("房间 {} 不存在或已关闭", code),
                    });
                }
                return;
            }
        };
        if !matches!(
            room.state,
            RoomState::WaitingGuest | RoomState::Relaying { .. }
        ) {
            if let Some(session) = st.sessions.get(session_id) {
                let _ = session.sender.send(ServerMessage::JoinFailed {
                    reason: "Host TUN is not ready; retry shortly".to_string(),
                });
            }
            return;
        }
        database::get_database()
            .and_then(|db| db.allocate_peer_ip(&code, session_id, "guest").ok())
            .unwrap_or_else(|| format!("{}.{}", room.subnet, room.guests.len() + 2))
    };
    let (host_sid, subnet, host_virtual_ip, guest_count) = {
        if let Some(room) = st.rooms.get_mut(&code) {
            // 不能加入自己的房间
            if room.host_session_id == session_id {
                if let Some(session) = st.sessions.get(session_id) {
                    let _ = session.sender.send(ServerMessage::Error {
                        message: "不能加入自己创建的房间".to_string(),
                    });
                }
                return;
            }

            // 加入
            room.guests.insert(session_id.to_string());
            let guest_count = room.guests.len();
            (
                room.host_session_id.clone(),
                room.subnet.clone(),
                room.host_virtual_ip.clone(),
                guest_count,
            )
        } else {
            // 房间不存在
            if let Some(session) = st.sessions.get(session_id) {
                let _ = session.sender.send(ServerMessage::JoinFailed {
                    reason: format!("房间 {} 不存在或已关闭", code),
                });
            }
            return;
        }
    };

    // 更新 guest 的 session 状态
    if let Some(session) = st.sessions.get_mut(session_id) {
        session.room_code = Some(code.clone());
        session.role = Some(Role::Guest);
        session.virtual_ip = Some(guest_virtual_ip.clone());
        let _ = session.sender.send(ServerMessage::JoinOk {
            room_code: code.clone(),
            host_session_id: host_sid.clone(),
            subnet: subnet.clone(),
            virtual_ip: guest_virtual_ip.clone(),
            host_virtual_ip: host_virtual_ip.clone(),
        });
    }

    // 通知 host 有人加入
    if let Some(host_session) = st.sessions.get(&host_sid) {
        info!("[房间] 向 Host {} 发送 PeerJoined 通知", host_sid);
        let _ = host_session.sender.send(ServerMessage::PeerJoined {
            peer_session_id: session_id.to_string(),
            guest_count,
        });
    } else {
        warn!(
            "[房间] Host {} 的 session 不存在，无法发送 PeerJoined",
            host_sid
        );
    }

    if let Some(db) = database::get_database() {
        let _ = db.update_guest_count(&code, guest_count as i32);
        let user_id = st
            .sessions
            .get(session_id)
            .and_then(|session| session.user_id.as_deref())
            .unwrap_or(session_id);
        let _ = db.log_event(user_id, Some(&code), "join_room", Some(&guest_virtual_ip));
    }

    info!(
        "[房间] {} 加入了房间 {} (子网: {}, 当前 {} 人)",
        session_id, code, subnet, guest_count
    );
}

/// 处理离开房间
async fn handle_leave_room(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    do_leave_room(session_id, &mut st);
}

/// 内部离开房间逻辑（也用于断开连接时的清理）
fn do_leave_room(session_id: &str, st: &mut AppState) {
    let (room_code, role) = {
        if let Some(session) = st.sessions.get(session_id) {
            match (&session.room_code, &session.role) {
                (Some(code), Some(role)) => (code.clone(), role.clone()),
                _ => return, // 不在房间中
            }
        } else {
            return;
        }
    };

    match role {
        Role::Host => {
            // Host 离开 = 关闭房间
            do_close_room_inner(session_id, &room_code, "host 断开连接", st);
        }
        Role::Guest => {
            let mut relay_state_to_release = None;
            // Guest 离开
            if let Some(room) = st.rooms.get_mut(&room_code) {
                room.guests.remove(session_id);
                // 打洞会话以 guest_session_id 为键，一次移除即可
                room.punch_sessions.remove(session_id);
                let guest_count = room.guests.len();

                // 房间内无 Guest 时回到待加入状态，避免复用过期中继 token
                if guest_count == 0 {
                    if matches!(room.state, RoomState::Relaying { .. }) {
                        relay_state_to_release = Some(room.state.clone());
                    }
                    room.state = RoomState::WaitingGuest;
                }

                // 通知 host
                if let Some(host_session) = st.sessions.get(&room.host_session_id) {
                    let _ = host_session.sender.send(ServerMessage::PeerLeft {
                        peer_session_id: session_id.to_string(),
                        guest_count,
                    });
                }

                info!(
                    "[房间] {} 离开了房间 {} (剩余 {} 人)",
                    session_id, room_code, guest_count
                );
            }

            if let Some(room_state) = relay_state_to_release {
                release_room_relay_token_if_needed(
                    &room_state,
                    st.relay_registry.clone(),
                    &room_code,
                );
            }

            // 清除 guest 的 session 状态
            if let Some(db) = database::get_database() {
                let _ = db.release_peer(&room_code, session_id);
                let _ = db.update_guest_count(
                    &room_code,
                    st.rooms
                        .get(&room_code)
                        .map(|r| r.guests.len() as i32)
                        .unwrap_or(0),
                );
            }
            if let Some(session) = st.sessions.get_mut(session_id) {
                session.room_code = None;
                session.role = None;
                session.virtual_ip = None;
            }
        }
    }
}

/// 处理关闭房间（仅 host）
async fn handle_close_room(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;

    // 验证是否为 host
    let room_code = {
        if let Some(session) = st.sessions.get(session_id) {
            match (&session.room_code, &session.role) {
                (Some(code), Some(Role::Host)) => code.clone(),
                _ => {
                    let _ = session.sender.send(ServerMessage::Error {
                        message: "你不是房间的 host，无法关闭房间".to_string(),
                    });
                    return;
                }
            }
        } else {
            return;
        }
    };

    do_close_room_inner(session_id, &room_code, "host 主动关闭", &mut st);
}

fn release_room_relay_token_if_needed(
    room_state: &RoomState,
    relay_registry: relay::SharedRegistry,
    room_code: &str,
) {
    if let RoomState::Relaying { token, .. } = room_state {
        let token = token.clone();
        let room_code = room_code.to_string();
        tokio::spawn(async move {
            let mut reg = relay_registry.lock().await;
            reg.consume_token(&token).await;
            info!("[中继] 房间 {} 释放中继 token: {}", room_code, token);
        });
    }
}

/// 内部关闭房间逻辑
fn do_close_room_inner(host_session_id: &str, room_code: &str, reason: &str, st: &mut AppState) {
    if let Some(room) = st.rooms.remove(room_code) {
        release_room_relay_token_if_needed(&room.state, st.relay_registry.clone(), room_code);
        // 房间没了就把中继补包额度收回来。客户端正常退出时会主动交还，
        // 但崩溃/断网就不会——不在这里兜底的话额度会一直泄漏，
        // 直到上限被占满、后续房间全部求援被拒。
        if st.relay_assist_rooms.remove(room_code) {
            info!(
                "[中继补包] 房间 {} 关闭，回收额度，当前 {}/{}",
                room_code,
                st.relay_assist_rooms.len(),
                st.config.relay.max_assist_rooms
            );
        }

        // 记录到数据库
        if let Some(db) = database::get_database() {
            let _ = db.close_room(room_code);
            let _ = db.update_guest_count(room_code, room.guests.len() as i32);
            let _ = db.release_room_network(room_code);
        }

        // 通知所有 guest 房间关闭
        for guest_sid in &room.guests {
            if let Some(guest_session) = st.sessions.get_mut(guest_sid) {
                let _ = guest_session.sender.send(ServerMessage::RoomClosed {
                    reason: reason.to_string(),
                });
                guest_session.room_code = None;
                guest_session.role = None;
                guest_session.virtual_ip = None;
            }
        }

        info!(
            "[房间] {} 关闭 (原因: {}, {} 个 guest 被通知)",
            room_code,
            reason,
            room.guests.len()
        );
    }

    // 清除 host 的 session 状态
    if let Some(session) = st.sessions.get_mut(host_session_id) {
        session.room_code = None;
        session.role = None;
        session.virtual_ip = None;
    }
}

// ============================================================
// 连接清理
// ============================================================

/// 清理断开连接的 session
async fn cleanup_session(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;

    // 先处理房间离开
    do_leave_room(session_id, &mut st);

    // 移除 session 并减少连接计数
    if let Some(session) = st.sessions.remove(session_id) {
        let ip_str = session.addr.ip().to_string();
        decrement_ip_connection_counter(&mut st, &ip_str);
    }
}

fn start_session_timeout_task(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            SESSION_SWEEP_INTERVAL_SECS,
        ));
        let timeout = tokio::time::Duration::from_secs(SESSION_HEARTBEAT_TIMEOUT_SECS);

        loop {
            ticker.tick().await;
            let now = tokio::time::Instant::now();

            // 先收集超时会话，避免持锁调用 cleanup_session 造成嵌套锁等待
            let expired_sessions: Vec<String> = {
                let st = state.lock().await;
                st.sessions
                    .iter()
                    .filter_map(|(sid, sess)| {
                        if now.duration_since(sess.last_activity) > timeout {
                            Some(sid.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            for sid in expired_sessions {
                warn!(
                    "[会话] {} 心跳超时（>{}s），执行断连清理",
                    sid, SESSION_HEARTBEAT_TIMEOUT_SECS
                );
                cleanup_session(&sid, &state).await;
            }
        }
    });
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "phantom_server=info".into()),
        )
        .init();

    let db = database::init_database()
        .unwrap_or_else(|e| panic!("[数据库] 初始化失败，拒绝以非持久化模式启动: {}", e));
    info!("[数据库] 初始化成功");
    if let Ok(c) = db.get_user_count() {
        info!("[数据库] 历史用户数: {}", c);
    }
    if let Ok(c) = db.get_room_count() {
        info!("[数据库] 历史房间数: {}", c);
    }

    let cfg = config::load_config();
    info!(
        "[配置] 信令={}:{}, 中继={}:{}(单端口), STUN={}/{}",
        cfg.signal.bind,
        cfg.signal.port,
        cfg.relay.public_addr,
        cfg.relay.quic_port,
        cfg.stun.port,
        cfg.stun.alt_port,
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("安装 CryptoProvider 失败");

    let relay_registry = Arc::new(Mutex::new(relay::RelayRegistry::new(
        cfg.relay.token_ttl_secs,
    )));
    relay::start_cleanup_task(relay_registry.clone());

    // 中继监听器在启动时起一次即可：房间路由靠流内 token，
    // 端口不参与识别，所有房间共用同一个端口。
    if let Err(e) = relay::start_quic_relay(cfg.relay.quic_port, relay_registry.clone()).await {
        error!("[中继] 启动失败: {}", e);
    }

    // 自建 STUN：打洞链路上不可绕过的一环，公共 STUN 失效就必然落中继
    if cfg.stun.enabled {
        if let Err(e) = stun_server::start(&cfg.signal.bind, cfg.stun.port, cfg.stun.alt_port).await
        {
            error!("[STUN] 启动失败: {}（客户端将只能使用兜底服务器）", e);
        }
    } else {
        warn!("[STUN] 自建 STUN 已禁用，客户端将依赖第三方公共服务器");
    }

    // 日志包接收服务：观测模型是集中式的，排障靠客户端上报
    let log_uploads = if cfg.log_upload.enabled {
        let base = cfg.log_upload.effective_base(&cfg.relay.public_addr);
        let reg = log_upload::UploadRegistry::new(
            std::path::PathBuf::from(&cfg.log_upload.store_dir),
            base.clone(),
        );
        match log_upload::start(&cfg.log_upload.bind, reg.clone()).await {
            Ok(()) => {
                info!("[日志上报] 客户端将上传至 {}", base);
                Some(reg)
            }
            Err(e) => {
                error!("[日志上报] 启动失败: {}", e);
                None
            }
        }
    } else {
        None
    };

    let cfg_arc = Arc::new(cfg.clone());
    let state = Arc::new(Mutex::new(AppState::new(
        relay_registry,
        log_uploads,
        cfg_arc.clone(),
    )));
    start_session_timeout_task(state.clone());

    admin::maybe_start(&cfg_arc, state.clone());

    let bind_addr = format!("{}:{}", cfg.signal.bind, cfg.signal.port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("无法绑定信令端口");
    info!("幻梦P2P 信令服务器启动于 {}", bind_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    handle_connection(stream, addr, state_clone).await;
                });
            }
            Err(e) => {
                warn!("[连接] accept 失败: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod sync_window_tests {
    use super::compute_start_delays;

    /// 两端实际起跑时刻必须对齐。
    ///
    /// 消息晚到的一方（RTT 大）等得少，早到的一方等得多，
    /// 两者相加后落在同一时刻。回归测试：早先下发的是绝对时间戳，
    /// 客户端拿自己的墙钟去比，时钟偏差直接等量破坏同步，实测偏差 3.5 秒。
    #[test]
    fn both_sides_start_at_the_same_moment() {
        let (host, guest) = compute_start_delays(400, 40);
        // host 单程 200ms、guest 单程 20ms，各自等待加上单程延迟应相等
        assert_eq!(host + 200, guest + 20, "两端起跑时刻应对齐");
    }

    /// RTT 差异越大，等待时长差异越大，方向必须正确
    #[test]
    fn slower_peer_waits_less() {
        let (slow, fast) = compute_start_delays(600, 20);
        assert!(slow < fast, "RTT 大的一方消息到得晚，应该等更短");
    }

    #[test]
    fn lead_is_clamped_to_sane_bounds() {
        // RTT 为 0 时也要留出最小提前量，否则等于没有同步
        let (h, g) = compute_start_delays(0, 0);
        assert_eq!((h, g), (500, 500));

        // RTT 极大时提前量封顶，不能让用户干等
        let (h, g) = compute_start_delays(10_000, 10_000);
        assert!(h <= 3_000 && g <= 3_000, "提前量必须封顶");
    }

    /// RTT 异常大于提前量时不能下溢成巨值
    #[test]
    fn extreme_rtt_does_not_underflow() {
        let (h, g) = compute_start_delays(60_000, 0);
        assert!(h <= 3_000 && g <= 3_000, "saturating_sub 应防住下溢");
    }
}
