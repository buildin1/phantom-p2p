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
mod port_pool;
mod relay;

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

/// ICE 候选缓存条目
#[derive(Clone)]
struct IceCandidateEntry {
    candidates: Vec<phantom_protocol::IceCandidate>,
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
    /// ICE 候选缓存：等双方都提交后再同步触发（session_id → 候选条目）
    ice_candidate_cache: HashMap<String, IceCandidateEntry>,
    /// ICE 鉴权信息缓存（session_id → (ufrag, pwd, nat_type)）
    ice_auth_info: HashMap<String, (String, String, String)>,
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
    /// 已启动的 QUIC 中继监听端口
    relay_quic_listener_ports: HashSet<u16>,
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
    fn new(relay_registry: relay::SharedRegistry, config: Arc<config::ServerConfig>) -> Self {
        Self {
            sessions: HashMap::new(),
            rooms: HashMap::new(),
            used_codes: HashSet::new(),
            next_session_seq: 1,
            subnet_counter: 0,
            rate_limit_create: HashMap::new(),
            rate_limit_connections: HashMap::new(),
            relay_registry,
            relay_quic_listener_ports: HashSet::new(),
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
        ClientMessage::Ping => {
            handle_ping(session_id, state).await;
        }
        ClientMessage::Auth {
            public_key,
            signature,
        } => {
            info!(
                "[鉴权] {} 收到 Auth 响应，公钥前4字节: {:?}, 签名长度: {}",
                session_id,
                &public_key[..4.min(public_key.len())],
                signature.len()
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
                ClientMessage::IceCandidates {
                    target_peer_session_id,
                    candidates,
                    ufrag,
                    pwd,
                    nat_type,
                } => {
                    handle_ice_candidates(
                        session_id,
                        target_peer_session_id,
                        candidates,
                        ufrag,
                        pwd,
                        nat_type,
                        state,
                    )
                    .await;
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
}

/// 记录客户端上报的最终连接模式（p2p / relay），仅供管理面板只读展示。
async fn handle_report_connection_mode(session_id: &str, mode: String, state: &SharedState) {
    let mut st = state.lock().await;
    if let Some(session) = st.sessions.get_mut(session_id) {
        info!("[连接模式] {} 上报: {}", session_id, mode);
        session.connection_mode = Some(mode);
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
        room.ice_candidate_cache.clear();
        room.ice_auth_info.clear();
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

async fn allocate_relay_slot(
    state: &SharedState,
    relay_registry: &relay::SharedRegistry,
    room_code: &str,
) -> Result<(String, u16), String> {
    const MAX_ATTEMPTS: usize = 8;

    for _ in 0..MAX_ATTEMPTS {
        let token = Uuid::new_v4().to_string();
        let excluded_ports = {
            let st = state.lock().await;
            st.relay_quic_listener_ports.clone()
        };
        let relay_port = {
            let mut reg = relay_registry.lock().await;
            match reg
                .register_token_excluding(token.clone(), &excluded_ports)
                .await
            {
                Some(port) => port,
                None => return Err("中继服务器端口资源不足，请稍后再试".to_string()),
            }
        };

        let need_start = {
            let st = state.lock().await;
            !st.relay_quic_listener_ports.contains(&relay_port)
        };

        if need_start {
            let start_result = relay::start_quic_relay(relay_port, relay_registry.clone()).await;

            if let Err(e) = start_result {
                error!(
                    "[中继] 房间 {} 监听端口 {} 启动失败: {}",
                    room_code, relay_port, e
                );
                let mut reg = relay_registry.lock().await;
                reg.consume_token(&token).await;
                reg.mark_port_unavailable(relay_port).await;
                continue;
            }

            let mut st = state.lock().await;
            st.relay_quic_listener_ports.insert(relay_port);
            info!(
                "[中继] 房间 {} 新增 QUIC 监听端口 {}",
                room_code, relay_port
            );
        }

        return Ok((token, relay_port));
    }

    Err("中继端口池无可用端口（监听初始化失败）".to_string())
}

async fn guest_relay_credential(registry: &relay::SharedRegistry, room_token: &str) -> String {
    let credential = Uuid::new_v4().to_string();
    registry
        .lock()
        .await
        .register_guest_credential(room_token, credential.clone());
    credential
}

/// 处理 ICE 候选上报：
///
/// 核心改进：**双边同步触发**。
/// 服务端收到第一方候选时先缓存，等双方都提交后，
/// 用同一个 start_at_ms 同时向双方下发对端候选，
/// 确保两端精确同步开始连通性检测，避免单边打洞失败。
async fn handle_ice_candidates(
    session_id: &str,
    target_peer_session_id: Option<String>,
    candidates: Vec<phantom_protocol::IceCandidate>,
    ufrag: String,
    pwd: String,
    nat_type: String,
    state: &SharedState,
) {
    // ── Step 1: 写入缓存，并检查是否双方均已就绪 ────────────────────
    let (room_code, relay_addr, relay_registry, trigger_pairs) = {
        let mut st = state.lock().await;

        // 先克隆不需要可变借用的字段
        let relay_addr = st.config.relay.public_addr.clone();
        let relay_registry = st.relay_registry.clone();

        let session = match st.sessions.get(session_id) {
            Some(s) => s,
            None => return,
        };
        let room_code = match &session.room_code {
            Some(c) => c.clone(),
            None => {
                let _ = session.sender.send(ServerMessage::Error {
                    message: "你不在房间中".to_string(),
                });
                return;
            }
        };
        let room = match st.rooms.get_mut(&room_code) {
            Some(r) => r,
            None => return,
        };

        // 写入本方候选缓存
        let host_sid = room.host_session_id.clone();
        let cache_key = if session_id == host_sid {
            target_peer_session_id
                .as_deref()
                .filter(|peer| room.guests.contains(*peer))
                .map(|peer| format!("{}::{}", session_id, peer))
                .unwrap_or_else(|| session_id.to_string())
        } else {
            session_id.to_string()
        };
        room.ice_candidate_cache.insert(
            cache_key.clone(),
            IceCandidateEntry {
                candidates: candidates.clone(),
            },
        );
        // 缓存鉴权信息（ufrag/pwd/nat_type）
        room.ice_auth_info
            .insert(cache_key, (ufrag.clone(), pwd.clone(), nat_type.clone()));

        // 检查 host 和所有 guest 是否都已提交
        let host_sid = room.host_session_id.clone();
        let guests: Vec<String> = room.guests.iter().cloned().collect();

        // 收集所有已缓存的 guest 候选及鉴权信息
        let ready_guests: Vec<(
            String,
            IceCandidateEntry,
            (String, String, String),
            IceCandidateEntry,
            (String, String, String),
        )> = guests
            .iter()
            .filter_map(|g| {
                let guest_entry = room.ice_candidate_cache.get(g).cloned()?;
                let guest_auth = room.ice_auth_info.get(g).cloned()?;
                let scoped_key = format!("{}::{}", host_sid, g);
                let host_entry = room
                    .ice_candidate_cache
                    .get(&scoped_key)
                    .or_else(|| room.ice_candidate_cache.get(&host_sid))
                    .cloned()?;
                let host_auth = room
                    .ice_auth_info
                    .get(&scoped_key)
                    .or_else(|| room.ice_auth_info.get(&host_sid))
                    .cloned()?;
                Some((g.clone(), host_entry, host_auth, guest_entry, guest_auth))
            })
            .collect();

        // trigger_pairs: (host_sid, host_entry, host_auth, ready_guests)
        // 只有 host 和至少一个 guest 都就绪时才触发
        let trigger_pairs = if !ready_guests.is_empty() {
            // Keep the Host candidate set. A Host socket is long-lived
            // and must be reusable for every later Guest. Removing it
            // here creates a race where a Guest joins after the first
            // timeout and no second ICE check is ever triggered.
            for (gsid, _, _, _, _) in &ready_guests {
                room.ice_candidate_cache.remove(gsid);
                room.ice_auth_info.remove(gsid);
                let scoped_key = format!("{}::{}", host_sid, gsid);
                room.ice_candidate_cache.remove(&scoped_key);
                room.ice_auth_info.remove(&scoped_key);
            }
            Some((host_sid.clone(), ready_guests))
        } else {
            None
        };

        (room_code.clone(), relay_addr, relay_registry, trigger_pairs)
    };

    info!(
        "[ICE] {} 上报 {} 个候选, NAT={}",
        session_id,
        candidates.len(),
        nat_type,
    );

    // ── Step 2: 双边同步下发（仅在双方均就绪时执行）────────────────
    if let Some((host_sid, ready_guests)) = trigger_pairs {
        // 用同一个 start_at_ms，给双方 200ms 窗口同步启动
        let start_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + 200;

        let st = state.lock().await;

        for (guest_sid, host_entry, host_auth, guest_entry, guest_auth) in &ready_guests {
            let (host_ufrag, host_pwd, host_nat_type) = host_auth;
            let (guest_ufrag, guest_pwd, guest_nat_type) = guest_auth;
            // 向 Guest 发送 Host 的候选
            if let Some(guest_sess) = st.sessions.get(guest_sid) {
                let _ = guest_sess.sender.send(ServerMessage::PeerCandidates {
                    peer_session_id: host_sid.clone(),
                    candidates: host_entry.candidates.clone(),
                    peer_ufrag: host_ufrag.clone(),
                    peer_pwd: host_pwd.clone(),
                    peer_nat_type: host_nat_type.clone(),
                    start_at_ms,
                });
            }
            // 向 Host 发送该 Guest 的候选
            if let Some(host_sess) = st.sessions.get(&host_sid) {
                let _ = host_sess.sender.send(ServerMessage::PeerCandidates {
                    peer_session_id: guest_sid.clone(),
                    candidates: guest_entry.candidates.clone(),
                    peer_ufrag: guest_ufrag.clone(),
                    peer_pwd: guest_pwd.clone(),
                    peer_nat_type: guest_nat_type.clone(),
                    start_at_ms,
                });
            }
        }

        info!(
            "[ICE] 房间 {} 双边同步触发: start_at_ms={}, {} 对",
            room_code,
            start_at_ms,
            ready_guests.len()
        );
    } else {
        info!(
            "[ICE] 房间 {} 缓存 {} 的候选，等待对端提交...",
            room_code, session_id
        );
    }

    // ── Step 3: 后台预分配中继（不阻塞当前处理）─────────────────────
    let state_clone = state.clone();
    let room_code_clone = room_code.clone();
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
async fn handle_ping(session_id: &str, state: &SharedState) {
    let mut st = state.lock().await;
    if let Some(session) = st.sessions.get_mut(session_id) {
        // 更新最后活动时间
        session.last_activity = tokio::time::Instant::now();
        let _ = session.sender.send(ServerMessage::Pong);
    }
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
        ice_candidate_cache: HashMap::new(),
        ice_auth_info: HashMap::new(),
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
                room.ice_candidate_cache.remove(session_id);
                room.ice_auth_info.remove(session_id);
                let scoped_key = format!("{}::{}", room.host_session_id, session_id);
                room.ice_candidate_cache.remove(&scoped_key);
                room.ice_auth_info.remove(&scoped_key);
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
        "[配置] 信令={}:{}, 中继端口池={}-{}, 中继地址={}",
        cfg.signal.bind,
        cfg.signal.port,
        cfg.relay.port_start,
        cfg.relay.port_end,
        cfg.relay.public_addr,
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("安装 CryptoProvider 失败");

    let relay_port_pool = Arc::new(Mutex::new(port_pool::RelayPortPool::new(
        cfg.relay.port_start,
        cfg.relay.port_end,
    )));
    let relay_registry = Arc::new(Mutex::new(relay::RelayRegistry::new(
        relay_port_pool,
        cfg.relay.token_ttl_secs,
    )));
    relay::start_cleanup_task(relay_registry.clone());

    let cfg_arc = Arc::new(cfg.clone());
    let state = Arc::new(Mutex::new(AppState::new(relay_registry, cfg_arc.clone())));
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
