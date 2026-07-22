//! 信令客户端 — WebSocket 连接管理
//!
//! 职责：
//! 1. 连接信令服务器（WebSocket）
//! 2. 发送/接收 MessagePack 消息
//! 3. 自动重连（指数退避）
//! 4. 心跳保活
//! 5. 将服务端消息转化为 Tauri 事件推送到前端

use futures_util::{SinkExt, StreamExt};
use phantom_protocol::{ClientMessage, ServerMessage};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::identity::Identity;

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

                        // 心跳定时器
                        let mut heartbeat_interval = time::interval(Duration::from_secs(15));
                        heartbeat_interval.reset(); // 避免立即触发

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
                                                        ServerMessage::Welcome { session_id: sid } => {
                                                            *session_id.write().await = Some(sid.clone());
                                                            info!("[信令] 收到 Welcome, session_id={}", sid);
                                                        }
                                                        ServerMessage::AuthChallenge { nonce } => {
                                                            info!("[鉴权] 收到 AuthChallenge，nonce 长度: {}", nonce.len());
                                                            // 自动签名响应
                                                            let sig = identity.sign(nonce.as_slice());
                                                            info!("[鉴权] 签名完成，签名长度: {}", sig.len());
                                                            let auth_msg = ClientMessage::Auth {
                                                                public_key: identity.public_key_bytes(),
                                                                signature: sig,
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
                                                        ServerMessage::Pong => {
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
                                    let ping_msg = ClientMessage::Ping;
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
