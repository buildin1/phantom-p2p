//! 信令客户端 — WebSocket 连接管理
//!
//! 职责：
//! 1. 连接信令服务器（WebSocket）
//! 2. 发送/接收 MessagePack 消息
//! 3. 自动重连（指数退避）
//! 4. 心跳保活
//! 5. 将服务端消息转化为 Tauri 事件推送到前端

use futures_util::{SinkExt, StreamExt};
use phantom_protocol::{ClientMessage, NetworkConfig, ServerMessage, PROTOCOL_VERSION};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::identity::Identity;

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================
// 连接状态
// ============================================================

/// 信令连接状态
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum ConnectionState {
    /// 未连接
    Disconnected,
    /// 连接中
    Connecting,
    /// 已连接
    Connected,
    /// 重连中 (第N次尝试)
    Reconnecting(u32),
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "未连接"),
            ConnectionState::Connecting => write!(f, "连接中"),
            ConnectionState::Connected => write!(f, "已连接"),
            ConnectionState::Reconnecting(n) => write!(f, "重连中(第{}次)", n),
        }
    }
}

// ============================================================
// 信令客户端
// ============================================================

/// 信令客户端
pub struct SignalClient {
    /// 当前连接状态
    state: Arc<RwLock<ConnectionState>>,
    /// 会话 ID（由服务端分配）
    session_id: Arc<RwLock<Option<String>>>,
    /// 当前所在房间
    room_code: Arc<RwLock<Option<String>>>,
    /// 发送消息的通道
    cmd_tx: Arc<Mutex<Option<mpsc::UnboundedSender<ClientMessage>>>>,
    /// 接收服务端消息的通道（供 Tauri 命令使用）
    event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ServerMessage>>>>,
    /// 共享的事件发送端（在连接 task 中写入）
    event_tx: Arc<mpsc::UnboundedSender<ServerMessage>>,
    /// 是否应该运行（用于优雅停止）
    running: Arc<RwLock<bool>>,
    /// 设备身份（Ed25519 密钥对）
    identity: Arc<Identity>,
    /// 是否允许日志输出真实信令地址（开发者模式）
    expose_signal_address: bool,
    /// 实测信令 RTT（毫秒）。由心跳往返测得，
    /// 服务端用它计算打洞的自适应同步窗口（固定偏移在跨省链路上等于没有同步）。
    signal_rtt_ms: Arc<AtomicU32>,
    /// 服务端下发的网络配置（STUN 列表、中继地址与端口）。
    /// 客户端不内置任何端口常量或 STUN 地址，一律以此为准。
    network_config: Arc<RwLock<Option<NetworkConfig>>>,
}

impl SignalClient {
    pub fn new(identity: Arc<Identity>, expose_signal_address: bool) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            session_id: Arc::new(RwLock::new(None)),
            room_code: Arc::new(RwLock::new(None)),
            cmd_tx: Arc::new(Mutex::new(None)),
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            event_tx: Arc::new(event_tx),
            running: Arc::new(RwLock::new(false)),
            identity,
            expose_signal_address,
            signal_rtt_ms: Arc::new(AtomicU32::new(0)),
            network_config: Arc::new(RwLock::new(None)),
        }
    }

    /// 最近一次实测的信令 RTT（毫秒）；尚未测得时返回 0
    pub fn signal_rtt_ms(&self) -> u32 {
        self.signal_rtt_ms.load(Ordering::Relaxed)
    }

    /// 设备长期身份密钥。打洞阶段用它为临时 X25519 公钥签名，
    /// 使对端能验证密钥未被信令服务器掉包。
    pub fn identity(&self) -> Arc<Identity> {
        self.identity.clone()
    }

    /// 服务端下发的网络配置；鉴权完成前为 None
    pub async fn network_config(&self) -> Option<NetworkConfig> {
        self.network_config.read().await.clone()
    }

    /// 等待服务端下发网络配置，最多等 `timeout`。
    ///
    /// 探测 NAT 画像**必须**先拿到 STUN 列表，否则会以空列表跑完探测、
    /// 得到 `class=Unknown` 且没有 srflx 候选，打洞从一开始就注定失败。
    /// 实测这个竞态确实会发生：配置未到时探测只花 4ms 就"完成"了。
    pub async fn wait_for_network_config(&self, timeout: Duration) -> Option<NetworkConfig> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(cfg) = self.network_config.read().await.clone() {
                return Some(cfg);
            }
            if tokio::time::Instant::now() >= deadline {
                warn!("[信令] 等待网络配置超时，STUN 列表为空将导致打洞失败");
                return None;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// 获取当前连接状态
    pub async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// 获取当前 session_id
    pub async fn get_session_id(&self) -> Option<String> {
        self.session_id.read().await.clone()
    }

    /// 获取当前房间码
    pub async fn get_room_code(&self) -> Option<String> {
        self.room_code.read().await.clone()
    }

    /// 取出事件接收端（只能调用一次，供 Tauri 事件循环使用）
    pub async fn take_event_rx(&self) -> Option<mpsc::UnboundedReceiver<ServerMessage>> {
        self.event_rx.lock().await.take()
    }

    /// 发送消息到服务端
    pub async fn send(&self, msg: ClientMessage) -> Result<(), String> {
        let tx = self.cmd_tx.lock().await;
        match tx.as_ref() {
            Some(tx) => tx.send(msg).map_err(|e| format!("发送失败: {}", e)),
            None => Err("未连接到信令服务器".to_string()),
        }
    }

    /// 连接到信令服务器（启动后台任务）
    pub async fn connect(&self, url: String) {
        // 标记为运行中
        *self.running.write().await = true;

        let state = self.state.clone();
        let session_id = self.session_id.clone();
        let room_code = self.room_code.clone();
        let cmd_tx = self.cmd_tx.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let identity = self.identity.clone();
        let expose_signal_address = self.expose_signal_address;
        let signal_rtt_ms = self.signal_rtt_ms.clone();
        let network_config = self.network_config.clone();

        tokio::spawn(async move {
            let mut retry_count: u32 = 0;
            let max_retry_delay = Duration::from_secs(30);

            loop {
                // 检查是否应该停止
                if !*running.read().await {
                    info!("[信令] 停止重连循环");
                    break;
                }

                // 更新状态
                if retry_count == 0 {
                    *state.write().await = ConnectionState::Connecting;
                } else {
                    *state.write().await = ConnectionState::Reconnecting(retry_count);
                }

                let log_url = if expose_signal_address {
                    url.clone()
                } else {
                    crate::config::redact_signal_url(&url)
                };
                info!("[信令] 连接到 {} (尝试 #{})", log_url, retry_count + 1);

                // 尝试连接
                match tokio_tungstenite::connect_async(&url).await {
                    Ok((ws_stream, _response)) => {
                        info!("[信令] WebSocket 连接成功");
                        *state.write().await = ConnectionState::Connected;
                        retry_count = 0; // 重置重试计数

                        let (mut ws_sink, mut ws_stream_read) = ws_stream.split();

                        // 创建命令通道
                        let (tx, mut cmd_rx) = mpsc::unbounded_channel::<ClientMessage>();
                        *cmd_tx.lock().await = Some(tx);

                        // 心跳定时器。
                        // **不 reset**：首个 tick 立即触发，让 RTT 尽早测出来。
                        // 之前 reset 后要等满 15 秒，而打洞往往在连上几秒内就发起，
                        // 于是画像里带的是 signal_rtt_ms=0，服务端据此算出的
                        // 同步窗口完全失真。
                        let mut heartbeat_interval = time::interval(Duration::from_secs(15));

                        // 消息循环
                        loop {
                            tokio::select! {
                                // 从服务端接收消息
                                msg = ws_stream_read.next() => {
                                    match msg {
                                        Some(Ok(Message::Binary(data))) => {
                                            match phantom_protocol::deserialize::<ServerMessage>(&data) {
                                                Ok(server_msg) => {
                                                    // 处理特殊消息（更新内部状态）
                                                    match &server_msg {
                                                        ServerMessage::Welcome { session_id: sid, protocol_version } => {
                                                            *session_id.write().await = Some(sid.clone());
                                                            info!("[信令] 收到 Welcome, session_id={}, 服务端协议版本={}", sid, protocol_version);
                                                            if *protocol_version != PROTOCOL_VERSION {
                                                                error!(
                                                                    "[信令] 协议版本不匹配：本机 {} / 服务端 {}。本协议不提供向后兼容，请升级客户端。",
                                                                    PROTOCOL_VERSION, protocol_version
                                                                );
                                                            }
                                                        }
                                                        ServerMessage::VersionMismatch {
                                                            server_protocol_version,
                                                            client_protocol_version,
                                                            message,
                                                        } => {
                                                            error!(
                                                                "[信令] 服务端拒绝连接：协议版本不匹配（本机 {} / 服务端 {}）：{}",
                                                                client_protocol_version, server_protocol_version, message
                                                            );
                                                            // 版本不兼容时重连也没有意义，停止重连循环
                                                            *running.write().await = false;
                                                        }
                                                        ServerMessage::NetworkConfigUpdate { config } => {
                                                            info!(
                                                                "[信令] 收到网络配置: {} 个 STUN 服务器, 中继 {}:{}",
                                                                config.stun_servers.len(),
                                                                config.relay_addr,
                                                                config.relay_quic_port
                                                            );
                                                            *network_config.write().await = Some(config.clone());
                                                        }
                                                        ServerMessage::AuthChallenge { nonce } => {
                                                            info!("[鉴权] 收到 AuthChallenge，nonce 长度: {}", nonce.len());
                                                            // 自动签名响应
                                                            let sig = identity.sign(nonce.as_slice());
                                                            info!("[鉴权] 签名完成，签名长度: {}", sig.len());
                                                            let auth_msg = ClientMessage::Auth {
                                                                public_key: identity.public_key_bytes(),
                                                                signature: sig,
                                                                protocol_version: PROTOCOL_VERSION,
                                                                client_version: env!("CARGO_PKG_VERSION").to_string(),
                                                            };
                                                            match phantom_protocol::serialize(&auth_msg) {
                                                                Ok(bytes) => {
                                                                    info!("[鉴权] Auth 消息序列化成功，大小: {} 字节", bytes.len());
                                                                    if let Err(e) = ws_sink.send(Message::Binary(bytes.into())).await {
                                                                        error!("[鉴权] 发送 Auth 失败: {}", e);
                                                                        break;
                                                                    }
                                                                    info!("[鉴权] 已发送 Auth 响应 (user: {})", identity.short_id());
                                                                }
                                                                Err(e) => {
                                                                    error!("[鉴权] 序列化 Auth 失败: {}", e);
                                                                }
                                                            }
                                                            // AuthChallenge 不转发到前端
                                                            continue;
                                                        }
                                                        ServerMessage::AuthOk { user_id } => {
                                                            info!("[鉴权] 认证成功 (user_id: {})", user_id);
                                                        }
                                                        ServerMessage::AuthFailed { reason } => {
                                                            error!("[鉴权] 认证失败: {}", reason);
                                                        }
                                                        ServerMessage::RoomCreated { room_code: code, .. } => {
                                                            *room_code.write().await = Some(code.clone());
                                                            info!("[信令] 房间已创建: {}", code);
                                                        }
                                                        ServerMessage::JoinOk { room_code: code, .. } => {
                                                            *room_code.write().await = Some(code.clone());
                                                            info!("[信令] 已加入房间: {}", code);
                                                        }
                                                        ServerMessage::RoomClosed { reason } => {
                                                            *room_code.write().await = None;
                                                            info!("[信令] 房间已关闭: {}", reason);
                                                        }
                                                        ServerMessage::Pong { client_time_ms, .. } => {
                                                            // 心跳往返测算信令 RTT，供服务端计算自适应同步窗口。
                                                            // 只用本机时钟做差，不依赖两端时钟同步。
                                                            let rtt = now_ms().saturating_sub(*client_time_ms);
                                                            if rtt <= 60_000 {
                                                                signal_rtt_ms.store(rtt as u32, Ordering::Relaxed);
                                                            }
                                                            // 心跳响应，不需要转发到前端
                                                            continue;
                                                        }
                                                        _ => {}
                                                    }

                                                    // 转发到事件通道（供前端消费）
                                                    let _ = event_tx.send(server_msg);
                                                }
                                                Err(e) => {
                                                    warn!("[信令] 反序列化失败: {}", e);
                                                }
                                            }
                                        }
                                        Some(Ok(Message::Close(_))) => {
                                            info!("[信令] 服务器关闭连接");
                                            break;
                                        }
                                        Some(Ok(_)) => {
                                            // 忽略 Text、Ping 等
                                        }
                                        Some(Err(e)) => {
                                            warn!("[信令] 读取错误: {}", e);
                                            break;
                                        }
                                        None => {
                                            info!("[信令] 连接已断开");
                                            break;
                                        }
                                    }
                                }

                                // 发送来自 Tauri 命令的消息
                                cmd = cmd_rx.recv() => {
                                    if let Some(client_msg) = cmd {
                                        // 添加调试日志
                                        info!("[信令] 准备发送消息: {:?}", client_msg);
                                        match phantom_protocol::serialize(&client_msg) {
                                            Ok(bytes) => {
                                                info!("[信令] 消息序列化成功，大小: {} 字节", bytes.len());
                                                if let Err(e) = ws_sink.send(Message::Binary(bytes.into())).await {
                                                    error!("[信令] 发送失败: {}", e);
                                                    break;
                                                }
                                                info!("[信令] 消息已发送到服务器");
                                            }
                                            Err(e) => {
                                                error!("[信令] 序列化失败: {}", e);
                                            }
                                        }
                                    } else {
                                        // 通道关闭
                                        break;
                                    }
                                }

                                // 心跳
                                _ = heartbeat_interval.tick() => {
                                    let ping_msg = ClientMessage::Ping { client_time_ms: now_ms() };
                                    match phantom_protocol::serialize(&ping_msg) {
                                        Ok(bytes) => {
                                            if let Err(e) = ws_sink.send(Message::Binary(bytes.into())).await {
                                                error!("[信令] 发送心跳失败: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("[信令] 序列化心跳失败: {}", e);
                                        }
                                    }
                                }
                            }
                        }

                        // 连接断开后清理
                        *cmd_tx.lock().await = None;
                        *session_id.write().await = None;
                        // 不清除 room_code，重连后可能需要恢复
                    }
                    Err(e) => {
                        error!("[信令] 连接失败: {}", e);
                    }
                }

                // 更新状态为断开
                *state.write().await = ConnectionState::Disconnected;

                // 检查是否应该停止
                if !*running.read().await {
                    break;
                }

                // 指数退避
                retry_count += 1;
                let delay = Duration::from_secs(std::cmp::min(
                    2u64.pow(retry_count.min(5)),
                    max_retry_delay.as_secs(),
                ));
                info!("[信令] {}秒后重连...", delay.as_secs());
                time::sleep(delay).await;
            }

            *state.write().await = ConnectionState::Disconnected;
            info!("[信令] 连接循环已停止");
        });
    }

    /// 断开连接
    pub async fn disconnect(&self) {
        *self.running.write().await = false;
        *self.cmd_tx.lock().await = None;
        *self.state.write().await = ConnectionState::Disconnected;
        *self.session_id.write().await = None;
        *self.room_code.write().await = None;
    }
}
