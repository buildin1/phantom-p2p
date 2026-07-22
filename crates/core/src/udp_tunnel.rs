//! UDP 隧道 — 裸 UDP 转发（不过 QUIC）
//!
//! P2P 模式：复用打洞 socket 直发
//! 中继模式：通过 relay UDP 端口转发
//!
//! 帧格式：[PP6U] [2字节长度 BE] [payload]
//! 用于区分打洞心跳包和游戏数据

use crate::stats::StatsManager;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, error, info, warn};

/// 帧魔数（4 字节）：区分游戏 UDP 包和打洞心跳
const FRAME_MAGIC: &[u8; 4] = b"PP6U";

/// 帧头长度 = 4 (magic) + 2 (length)
const FRAME_HEADER_LEN: usize = 6;

/// 最大 UDP 负载
const MAX_PAYLOAD: usize = 65000;

/// UDP 隧道模式
#[derive(Debug, Clone)]
pub enum UdpTunnelMode {
    /// P2P 直连（复用打洞 socket）
    P2P {
        /// 打洞成功的 UDP socket
        punch_socket: Arc<UdpSocket>,
        /// 对端地址
        peer_addr: SocketAddr,
    },
    /// 中继模式
    Relay {
        /// 中继服务器地址
        relay_addr: SocketAddr,
        /// 中继 token（在首包中发送用于配对）
        token: String,
    },
}

/// 启动 Host 侧 UDP 隧道
///
/// 外部 UDP（从对端/中继收到的帧）→ 解帧 → 转发到本地 game_port
/// 本地 game_port 的 UDP 响应 → 封帧 → 发到对端/中继
pub async fn start_host_udp_tunnel(
    mode: UdpTunnelMode,
    game_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<(), String> {
    // 本地 UDP socket，连接到游戏服务器
    let local_sock = TokioUdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("绑定本地 UDP 失败: {}", e))?;

    let game_addr: SocketAddr = format!("127.0.0.1:{}", game_port).parse().unwrap();

    info!(
        "[UDP-Host] 启动 (游戏端口: {}, 模式: {:?})",
        game_port,
        match &mode {
            UdpTunnelMode::P2P { peer_addr, .. } => format!("P2P→{}", peer_addr),
            UdpTunnelMode::Relay { relay_addr, .. } => format!("Relay→{}", relay_addr),
        }
    );

    match mode {
        UdpTunnelMode::P2P {
            punch_socket,
            peer_addr,
        } => {
            // 将 std UdpSocket 转为 tokio UdpSocket
            punch_socket
                .set_nonblocking(true)
                .map_err(|e| format!("设置非阻塞失败: {}", e))?;
            let punch_sock = TokioUdpSocket::from_std(
                punch_socket
                    .try_clone()
                    .map_err(|e| format!("克隆 socket 失败: {}", e))?,
            )
            .map_err(|e| format!("转换 tokio socket 失败: {}", e))?;

            host_udp_loop(
                Arc::new(punch_sock),
                peer_addr,
                local_sock,
                game_addr,
                stats_manager,
                user_id,
            )
            .await;
        }
        UdpTunnelMode::Relay { relay_addr, token } => {
            let relay_sock = TokioUdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("绑定中继 UDP 失败: {}", e))?;

            // 发送 token 首包用于配对
            let token_frame = build_token_frame(&token);
            relay_sock
                .send_to(&token_frame, relay_addr)
                .await
                .map_err(|e| format!("发送中继 token 失败: {}", e))?;

            info!("[UDP-Host] 已发送中继 token");
            host_udp_loop(
                Arc::new(relay_sock),
                relay_addr,
                local_sock,
                game_addr,
                stats_manager,
                user_id,
            )
            .await;
        }
    }

    Ok(())
}

/// 启动 Guest 侧 UDP 隧道
///
/// 本地 local_port 收到的 UDP 包 → 封帧 → 发到对端/中继
/// 从对端/中继收到的帧 → 解帧 → 发回本地客户端
///
/// 返回实际监听的端口号
pub async fn start_guest_udp_tunnel(
    mode: UdpTunnelMode,
    local_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<u16, String> {
    match mode {
        UdpTunnelMode::P2P {
            punch_socket,
            peer_addr: _peer_addr,
        } => {
            // P2P 模式：直接使用打洞的 socket，不需要绑定新端口
            punch_socket
                .set_nonblocking(true)
                .map_err(|e| format!("设置非阻塞失败: {}", e))?;

            let actual_port = punch_socket.local_addr().map(|a| a.port()).unwrap_or(0);

            info!(
                "[UDP-Guest] P2P 模式使用打洞 socket (端口: {})",
                actual_port
            );

            // P2P 模式下，punch_socket 既是外部通信 socket，也是本地监听 socket
            // 不需要额外的转发，游戏直接通过这个 socket 通信
            tokio::spawn(async move {
                // 这里实际上不需要转发循环，因为游戏会直接使用这个 socket
                // 但为了保持接口一致，我们保留这个任务
                info!("[UDP-Guest] P2P UDP 隧道已就绪");
            });

            Ok(actual_port)
        }
        UdpTunnelMode::Relay { relay_addr, token } => {
            // 中继模式：需要绑定本地端口用于游戏连接
            let bind_addr = format!("127.0.0.1:{}", local_port);
            let local_sock = match TokioUdpSocket::bind(&bind_addr).await {
                Ok(sock) => sock,
                Err(e) if e.kind() == ErrorKind::AddrInUse => {
                    warn!(
                        "[UDP-Guest] 本地端口 {} 被占用，自动回退到随机端口",
                        local_port
                    );
                    TokioUdpSocket::bind("127.0.0.1:0")
                        .await
                        .map_err(|fallback_err| {
                            format!(
                                "绑定本地 UDP {} 失败且随机端口回退失败: {} / {}",
                                bind_addr, e, fallback_err
                            )
                        })?
                }
                Err(e) => {
                    return Err(format!("绑定本地 UDP {} 失败: {}", bind_addr, e));
                }
            };

            let actual_port = local_sock
                .local_addr()
                .map(|a| a.port())
                .unwrap_or(local_port);

            info!(
                "[UDP-Guest] 监听 127.0.0.1:{} (模式: Relay→{})",
                actual_port, relay_addr
            );

            let relay_sock = TokioUdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("绑定中继 UDP 失败: {}", e))?;

            // 发送 token 首包
            let token_frame = build_token_frame(&token);
            relay_sock
                .send_to(&token_frame, relay_addr)
                .await
                .map_err(|e| format!("发送中继 token 失败: {}", e))?;

            info!("[UDP-Guest] 已发送中继 token");
            tokio::spawn(async move {
                guest_udp_loop(
                    Arc::new(relay_sock),
                    relay_addr,
                    local_sock,
                    stats_manager,
                    user_id,
                )
                .await;
            });

            Ok(actual_port)
        }
    }
}

// ============================================================
// 内部转发循环
// ============================================================

/// Host 侧 UDP 转发循环
async fn host_udp_loop(
    external_sock: Arc<TokioUdpSocket>,
    peer_addr: SocketAddr,
    local_sock: TokioUdpSocket,
    game_addr: SocketAddr,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) {
    let local_sock = Arc::new(local_sock);
    let external_sock2 = external_sock.clone();
    let external_sock3 = external_sock.clone();
    let local_sock2 = local_sock.clone();
    let stats_inbound = stats_manager.clone();
    let user_inbound = user_id.clone();
    let stats_outbound = stats_manager;
    let user_outbound = user_id;

    // 心跳任务：每 1 秒发送一次空帧保持 NAT 映射（运营商级 NAT 超时很短）
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let heartbeat_frame = encode_frame(&[]); // 空帧作为心跳
            if let Err(e) = external_sock3.send_to(&heartbeat_frame, peer_addr).await {
                warn!("[UDP-Host] 发送心跳失败: {}", e);
                break;
            }
            debug!("[UDP-Host] 已发送心跳到 {}", peer_addr);
        }
    });

    // 外部→本地：从对端收帧 → 解帧 → 转发到游戏
    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PAYLOAD + FRAME_HEADER_LEN + 100];
        loop {
            match external_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if let Some(payload) = decode_frame(&buf[..n]) {
                        // 空帧是心跳，不转发
                        if payload.is_empty() {
                            debug!("[UDP-Host] 收到心跳来自 {}", from);
                            continue;
                        }
                        stats_inbound
                            .record_receive(&user_inbound, payload.len())
                            .await;
                        if let Err(e) = local_sock.send_to(payload, game_addr).await {
                            warn!("[UDP-Host] 转发到游戏失败: {}", e);
                        }
                    }
                    // 非游戏帧（如打洞心跳）忽略
                }
                Err(e) => {
                    error!("[UDP-Host] 接收外部 UDP 失败: {}", e);
                    break;
                }
            }
        }
    });

    // 本地→外部：游戏响应 → 封帧 → 发到对端
    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        loop {
            match local_sock2.recv_from(&mut buf).await {
                Ok((n, _from)) => {
                    stats_outbound.record_send(&user_outbound, n).await;
                    let frame = encode_frame(&buf[..n]);
                    if let Err(e) = external_sock2.send_to(&frame, peer_addr).await {
                        warn!("[UDP-Host] 发送到对端失败: {}", e);
                    }
                }
                Err(e) => {
                    error!("[UDP-Host] 接收游戏 UDP 失败: {}", e);
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(heartbeat, inbound, outbound);
}

/// Guest 侧 UDP 转发循环
async fn guest_udp_loop(
    external_sock: Arc<TokioUdpSocket>,
    peer_addr: SocketAddr,
    local_sock: TokioUdpSocket,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) {
    let local_sock = Arc::new(local_sock);
    let external_sock2 = external_sock.clone();
    let external_sock3 = external_sock.clone();
    let local_sock2 = local_sock.clone();
    let stats_outbound = stats_manager.clone();
    let user_outbound = user_id.clone();
    let stats_inbound = stats_manager;
    let user_inbound = user_id;

    // 记录最近的本地客户端地址（游戏客户端的地址）
    let client_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let client_addr2 = client_addr.clone();

    // 心跳任务：每 1 秒发送一次空帧保持 NAT 映射（运营商级 NAT 超时很短）
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let heartbeat_frame = encode_frame(&[]); // 空帧作为心跳
            if let Err(e) = external_sock3.send_to(&heartbeat_frame, peer_addr).await {
                warn!("[UDP-Guest] 发送心跳失败: {}", e);
                break;
            }
            debug!("[UDP-Guest] 已发送心跳到 {}", peer_addr);
        }
    });

    // 本地→外部：本地游戏客户端 → 封帧 → 发到对端
    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        loop {
            match local_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    // 记录客户端地址
                    *client_addr.lock().await = Some(from);
                    stats_outbound.record_send(&user_outbound, n).await;
                    let frame = encode_frame(&buf[..n]);
                    if let Err(e) = external_sock.send_to(&frame, peer_addr).await {
                        warn!("[UDP-Guest] 发送到对端失败: {}", e);
                    }
                }
                Err(e) => {
                    error!("[UDP-Guest] 接收本地 UDP 失败: {}", e);
                    break;
                }
            }
        }
    });

    // 外部→本地：从对端收帧 → 解帧 → 发回本地客户端
    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PAYLOAD + FRAME_HEADER_LEN + 100];
        loop {
            match external_sock2.recv_from(&mut buf).await {
                Ok((n, _from)) => {
                    if let Some(payload) = decode_frame(&buf[..n]) {
                        // 空帧是心跳，不转发
                        if payload.is_empty() {
                            debug!("[UDP-Guest] 收到心跳来自 {}", _from);
                            continue;
                        }
                        stats_inbound
                            .record_receive(&user_inbound, payload.len())
                            .await;
                        let addr = client_addr2.lock().await;
                        if let Some(client) = *addr {
                            if let Err(e) = local_sock2.send_to(payload, client).await {
                                warn!("[UDP-Guest] 转发到本地客户端失败: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("[UDP-Guest] 接收外部 UDP 失败: {}", e);
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(heartbeat, outbound, inbound);
}

// ============================================================
// 帧编解码
// ============================================================

/// 编码数据帧：[PP6U][2字节长度BE][payload]
fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// 解码数据帧，返回 payload 切片；非法帧返回 None
fn decode_frame(data: &[u8]) -> Option<&[u8]> {
    if data.len() < FRAME_HEADER_LEN {
        return None;
    }
    if &data[..4] != FRAME_MAGIC {
        return None;
    }
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < FRAME_HEADER_LEN + len {
        return None;
    }
    Some(&data[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len])
}

/// 构建中继 token 首包：[PPTK][token bytes]
fn build_token_frame(token: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + token.len());
    frame.extend_from_slice(b"PPTK");
    frame.extend_from_slice(token.as_bytes());
    frame
}
