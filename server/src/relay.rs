//! 中继服务器 — 单端口 QUIC 中继
//!
//! # 两级复用
//!
//! 1. **房间内**：一个 token 对应一个 Host 连接 + N 个 Guest 连接，
//!    所有 Guest 的流通过共享的 Host 连接桥接（FRP 代理模型）。
//! 2. **房间间**：所有房间共用**同一个** QUIC 监听端口。
//!    房间标识完全来自首流里的 token，端口从不参与路由——
//!    QUIC 本就靠 Connection ID 而非四元组区分连接，
//!    每房间一个端口是在浪费这个能力，还把并发上限锁死在端口数上。
//!
//! 曾经存在的 UDP 裸转发路径已删除：它从未被生产代码启动过
//! （唯一调用点在自己的单元测试里），而数据面统一走 QUIC 之后，
//! 单独维护一条明文通道只会让两套逻辑的 bug 互相掩盖。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PIP1_STREAM_MAGIC: &[u8; 4] = b"PIP1";

fn is_pip1_stream(prefix: &[u8; 4]) -> bool {
    prefix == PIP1_STREAM_MAGIC
}

// ============================================================
// 共享 Token 注册表
// ============================================================

/// 等待配对的 Token 条目
struct PendingToken {
    created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayPeerRole {
    Host,
    Guest,
    Unknown,
}

fn parse_quic_token_payload(payload: &str) -> (String, RelayPeerRole) {
    if let Some(token) = payload.strip_prefix("host|") {
        return (token.to_string(), RelayPeerRole::Host);
    }
    if let Some(token) = payload.strip_prefix("guest|") {
        return (token.to_string(), RelayPeerRole::Guest);
    }
    (payload.to_string(), RelayPeerRole::Unknown)
}

fn relay_role_name(role: RelayPeerRole) -> &'static str {
    match role {
        RelayPeerRole::Host => "host",
        RelayPeerRole::Guest => "guest",
        RelayPeerRole::Unknown => "unknown",
    }
}

fn resolve_room_token(
    registry: &RelayRegistry,
    credential: &str,
    role: RelayPeerRole,
) -> Option<String> {
    match role {
        RelayPeerRole::Host if registry.is_valid(credential) => Some(credential.to_string()),
        RelayPeerRole::Guest => registry
            .guest_credentials
            .get(credential)
            .filter(|room_token| registry.is_valid(room_token))
            .cloned(),
        _ => None,
    }
}

/// 中继 Token 注册表（信令和中继共享）
///
/// 1:N 模型：
/// - 一个 token 下最多有一个 host_connection
/// - 一个 token 下可以有多个 guest_connection（pending 或已桥接）
/// - token 在房间关闭前一直有效
/// **所有房间共用一个 QUIC 端口。**
///
/// 房间路由完全靠首流里的 token（见 [`handle_quic_relay_conn`]），
/// 监听端口从不参与识别。原先"每房间一个端口"是历史遗留的冗余维度，
/// 还把并发上限人为限制在端口数上——而真实瓶颈是带宽，不是端口。
pub struct RelayRegistry {
    /// token 有效期
    #[allow(dead_code)]
    token_timeout: Duration,
    /// 有效的房间 token
    pending: HashMap<String, PendingToken>,
    /// opaque guest ticket -> room token; guests never receive the host token
    guest_credentials: HashMap<String, String>,
    /// 已注册的 Host QUIC 连接（token → host_conn）
    /// 一个 token 只能有一个 Host 连接
    host_connections: HashMap<String, quinn::Connection>,
    /// 等待 Host 连接的 Guest waiter（token → [tx]）
    /// Guest 连接到达但 Host 未到时，通过 oneshot 等待通知
    guest_host_waiters: HashMap<String, Vec<oneshot::Sender<()>>>,
}

impl RelayRegistry {
    pub fn new(token_ttl_secs: u64) -> Self {
        Self {
            token_timeout: Duration::from_secs(token_ttl_secs.max(1)),
            pending: HashMap::new(),
            guest_credentials: HashMap::new(),
            host_connections: HashMap::new(),
            guest_host_waiters: HashMap::new(),
        }
    }

    /// 登记一个房间 token。不再分配端口——所有房间共用同一个监听端口。
    pub fn register_token(&mut self, token: String) {
        self.pending.insert(
            token.clone(),
            PendingToken {
                created_at: Instant::now(),
            },
        );
        info!("[中继注册] token:{} 已登记", token);
    }

    /// 检查 token 是否有效
    pub fn is_valid(&self, token: &str) -> bool {
        self.pending.contains_key(token)
    }

    /// 释放 token（房间关闭，或全员已切到 P2P 直连时调用）
    pub async fn consume_token(&mut self, token: &str) {
        self.pending.remove(token);
        self.host_connections.remove(token);
        if let Some(waiters) = self.guest_host_waiters.remove(token) {
            for w in waiters {
                let _ = w.send(());
            }
        }
        self.guest_credentials.retain(|_, room| room != token);
    }

    pub fn register_guest_credential(&mut self, room_token: &str, credential: String) {
        self.guest_credentials
            .insert(credential, room_token.to_string());
    }

    /// 当前占用中继资源的房间数（容量观测用）
    pub fn active_room_count(&self) -> usize {
        self.pending.len()
    }

    /// 清理过期 token
    pub async fn cleanup_expired(&mut self) {
        // Room tokens are leases, not short-lived handshakes. They are
        // released explicitly when the room closes so late joiners and
        // reconnecting peers keep working for the whole room lifetime.
    }
}

pub type SharedRegistry = Arc<Mutex<RelayRegistry>>;

// ============================================================
// QUIC 中继（TCP 游戏）— 1:N 多路复用
// ============================================================

/// 启动 QUIC 中继监听
pub async fn start_quic_relay(bind_port: u16, registry: SharedRegistry) -> Result<(), String> {
    let (cert_der, key_der) = generate_self_signed_cert()?;
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("私钥格式错误: {}", e))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("TLS 配置失败: {}", e))?;
    server_crypto.alpn_protocols = vec![b"phantom-relay".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("QUIC 中继配置失败: {}", e))?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    // 数据面走 DATAGRAM（见 phantom_core::tun_bridge），中继必须收得下：
    // 缓冲太小会在突发时把包丢在中继自己手上，看起来像网络丢包，极难排查。
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .map_err(|e| format!("QUIC 中继绑定 {} 失败: {}", bind_addr, e))?;

    info!("[中继-QUIC] 监听 {}", bind_addr);

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let registry = registry.clone();
            tokio::spawn(async move {
                handle_quic_relay_conn(incoming, registry).await;
            });
        }
    });

    Ok(())
}

/// 处理单个 QUIC 中继连接（1:N 多路复用版）
///
/// 新逻辑：
/// - Host 连接：存储为 host_conn，桥接所有等待中的 Guest 连接，通知 waiter
/// - Guest 连接：如果 host_conn 已存在则直接桥接，否则暂存为 pending 并等待 Host
async fn handle_quic_relay_conn(incoming: quinn::Incoming, registry: SharedRegistry) {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            warn!("[中继-QUIC] 连接失败: {}", e);
            return;
        }
    };

    let remote = conn.remote_address();
    info!("[中继-QUIC] 新连接来自 {}", remote);

    // 接收第一条流，读取 token
    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            warn!("[中继-QUIC] {} 接收首流失败: {}", remote, e);
            return;
        }
    };

    let token_payload = match recv.read_to_end(256).await {
        Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).to_string(),
        _ => {
            warn!("[中继-QUIC] {} 读取 token 失败", remote);
            return;
        }
    };
    let (credential, role) = parse_quic_token_payload(&token_payload);

    info!(
        "[中继-QUIC] {} 提交 token: {} (role={})",
        remote,
        credential,
        relay_role_name(role)
    );

    let token = {
        let reg = registry.lock().await;
        resolve_room_token(&reg, &credential, role)
    };
    let Some(token) = token else {
        warn!(
            "[中继-QUIC] {} role={} credential 无效",
            remote,
            relay_role_name(role)
        );
        let _ = send.write_all(b"ERR:invalid_credential").await;
        let _ = send.finish();
        return;
    };

    match role {
        RelayPeerRole::Host => {
            handle_host_conn(conn, token, send, registry).await;
        }
        RelayPeerRole::Guest => {
            handle_guest_conn(conn, token, send, registry).await;
        }
        RelayPeerRole::Unknown => {
            warn!("[中继-QUIC] {} 未知角色 token: {}", remote, token);
            let _ = send.write_all(b"ERR:unknown_role").await;
            let _ = send.finish();
        }
    }
}

/// 处理 Host 连接注册
///
/// 1. 验证 token
/// 2. 替换旧的 host_conn（如果有）
/// 3. 通知正在等待 Host 的 Guest waiter，由各 Guest 唯一地启动桥接
/// 4. 回复 OK
async fn handle_host_conn(
    conn: quinn::Connection,
    token: String,
    mut send: quinn::SendStream,
    registry: SharedRegistry,
) {
    // 需要持有 lock 的临界区尽量短
    let (token_valid, duplicate_host, pending_guest_count) = {
        let mut reg = registry.lock().await;
        if !reg.is_valid(&token) {
            (false, false, 0)
        } else if reg
            .host_connections
            .get(&token)
            .is_some_and(|old_host| old_host.close_reason().is_none())
        {
            // A room owns one long-lived Host connection. A later Guest must
            // not cause a repeated RelayReady to evict that connection.
            (true, true, 0)
        } else {
            reg.host_connections.remove(&token);
            reg.host_connections.insert(token.clone(), conn.clone());

            // 通知所有等待 Host 的 Guest waiter
            let waiters = reg.guest_host_waiters.remove(&token).unwrap_or_default();
            let mut pending_count = 0;
            for waiter in waiters {
                if waiter.send(()).is_ok() {
                    pending_count += 1;
                }
            }

            (true, false, pending_count)
        }
    };

    if !token_valid {
        warn!("[中继-QUIC] Host token 无效或过期: {}", token);
        let _ = send.write_all(b"ERR:invalid_token").await;
        let _ = send.finish();
        return;
    }

    if duplicate_host {
        warn!(
            "[Relay-QUIC] token:{} rejected duplicate live Host connection; existing Guests remain attached",
            token
        );
        let _ = send.write_all(b"ERR:dup_host").await;
        let _ = send.finish();
        conn.close(0u32.into(), b"duplicate host connection");
        return;
    }

    info!(
        "[中继-QUIC] Host 注册成功 token:{}，桥接 {} 个等待的 Guest",
        token, pending_guest_count
    );

    // Host 回复 OK（无需等待）
    let _ = send.write_all(b"OK").await;
    let _ = send.finish();
}

/// 处理 Guest 连接注册
///
/// 1. 验证 token
/// 2. 如果 host_conn 已存在 → 直接桥接，回复 OK
/// 3. 如果 host_conn 不存在 → 暂存为 pending，等待 Host（带超时）
async fn handle_guest_conn(
    conn: quinn::Connection,
    token: String,
    mut send: quinn::SendStream,
    registry: SharedRegistry,
) {
    // 尝试立即桥接或暂存
    let (host_conn_opt, need_wait, wait_rx) = {
        let mut reg = registry.lock().await;
        if !reg.is_valid(&token) {
            (None, false, None)
        } else if let Some(host_conn) = reg
            .host_connections
            .get(&token)
            .filter(|host_conn| host_conn.close_reason().is_none())
            .cloned()
        {
            // Host 已在线，直接桥接
            (Some(host_conn), false, None)
        } else {
            reg.host_connections.remove(&token);
            // Host 尚未连接；当前任务持有 conn，只登记一次性唤醒器。
            let (tx, rx) = oneshot::channel::<()>();
            reg.guest_host_waiters
                .entry(token.clone())
                .or_insert_with(Vec::new)
                .push(tx);

            (None, true, Some(rx))
        }
    };

    match host_conn_opt {
        Some(host_conn) => {
            // Host 已在线，立即桥接
            info!("[中继-QUIC] Guest 直接桥接到 Host (token: {})", token);
            let _ = send.write_all(b"OK").await;
            let _ = send.finish();
            tokio::spawn(bridge_guest_to_host(conn, host_conn));
        }
        None if need_wait => {
            // 等待 Host 连接（或超时）
            let wait_timeout = {
                let reg = registry.lock().await;
                reg.token_timeout + Duration::from_secs(2)
            };

            // 先回复 OK，让 Guest 侧先开始准备（实际流桥接在 host 到达后启动）
            let _ = send.write_all(b"OK").await;
            let _ = send.finish();

            let wait_result = if let Some(rx) = wait_rx {
                tokio::time::timeout(wait_timeout, rx).await.is_ok()
            } else {
                false
            };

            if wait_result {
                info!(
                    "[中继-QUIC] Guest 等待 Host 到达成功，开始桥接 (token: {})",
                    token
                );
                // 从 registry 重新获取 host_conn（wait 期间 host 已注册）
                let host_conn_after_wait = {
                    let reg = registry.lock().await;
                    reg.host_connections
                        .get(&token)
                        .filter(|host_conn| host_conn.close_reason().is_none())
                        .cloned()
                };
                if let Some(host_conn) = host_conn_after_wait {
                    tokio::spawn(bridge_guest_to_host(conn, host_conn));
                }
                // 如果获取不到 host_conn，说明期间 token 被消耗了，静默退出
            } else {
                warn!("[中继-QUIC] Guest 等待 Host 超时 (token: {})", token);
                let mut reg = registry.lock().await;
                if let Some(waiters) = reg.guest_host_waiters.get_mut(&token) {
                    waiters.retain(|waiter| !waiter.is_closed());
                    if waiters.is_empty() {
                        reg.guest_host_waiters.remove(&token);
                    }
                }
            }
        }
        _ => {
            warn!("[中继-QUIC] Guest token 无效或过期: {}", token);
            let _ = send.write_all(b"ERR:invalid_token").await;
            let _ = send.finish();
        }
    }
}

/// Guest → Host 单向流桥接
///
/// 只从 Guest 侧 accept 流，然后打开 Host 侧的流进行桥接。
/// 因为 Host 侧 relay_host_tcp_loop 会 accept 所有来自中继的流，
/// 所以不需要"Host → Guest"方向的 accept。
///
/// 注意：relay_streams 本身是双向的（a_recv→b_send, b_recv→a_send），
/// 所以一个流就实现了 Guest↔Host 全双工通信。
/// 单向盲转发 QUIC 数据报。
///
/// **中继必须转发 datagram**，因为客户端的三层数据面（`phantom_core::tun_bridge`）
/// 完全走 DATAGRAM 而不是流——只转发流的话中继模式下隧道根本不通。
///
/// 中继在这里是**纯盲转发器**：载荷由 overlay 层端到端加密（`phantom_core::crypto`），
/// 前向纠错的分组头虽然是明文，中继也不需要理解——FEC 闭环完全在两个客户端之间完成，
/// 中继零状态、零 CPU 开销。
fn spawn_datagram_relay(from: quinn::Connection, to: quinn::Connection, label: &'static str) {
    tokio::spawn(async move {
        loop {
            match from.read_datagram().await {
                Ok(datagram) => {
                    if let Err(e) = to.send_datagram(datagram) {
                        // 对端缓冲满或连接已关：丢这一个继续跑，
                        // 数据面本就是不可靠语义，不该因此拆掉整条桥。
                        debug!("[中继桥接] {} 数据报转发失败: {}", label, e);
                        if to.close_reason().is_some() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("[中继桥接] {} 数据报来源结束: {}", label, e);
                    break;
                }
            }
        }
    });
}

async fn bridge_guest_to_host(guest_conn: quinn::Connection, host_conn: quinn::Connection) {
    let remote_guest = guest_conn.remote_address();
    let remote_host = host_conn.remote_address();
    info!(
        "[中继桥接] Guest({}) ↔ Host({}) 开始",
        remote_guest, remote_host
    );

    // 三层数据面走 DATAGRAM，必须双向盲转发
    spawn_datagram_relay(guest_conn.clone(), host_conn.clone(), "Guest→Host");
    spawn_datagram_relay(host_conn.clone(), guest_conn.clone(), "Host→Guest");

    loop {
        match guest_conn.accept_bi().await {
            Ok((mut guest_send, mut guest_recv)) => {
                let hc = host_conn.clone();
                tokio::spawn(async move {
                    let mut prefix = [0u8; 4];
                    if guest_recv.read_exact(&mut prefix).await.is_err() {
                        let _ = guest_send.finish();
                        return;
                    }
                    if !is_pip1_stream(&prefix) {
                        warn!(
                            "[中继桥接] Guest({}) 提交了非 PIP1 流，已拒绝",
                            remote_guest
                        );
                        let _ = guest_send.finish();
                        return;
                    }

                    match hc.open_bi().await {
                        Ok((mut host_send, host_recv)) => {
                            if host_send.write_all(&prefix).await.is_err() {
                                let _ = guest_send.finish();
                                return;
                            }
                            relay_streams(guest_recv, host_send, host_recv, guest_send).await;
                        }
                        Err(e) => {
                            warn!(
                                "[中继桥接] 打开 Host 流失败 {} → {}: {}",
                                remote_guest, remote_host, e
                            );
                        }
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("[中继桥接] Guest({}) 主动关闭连接", remote_guest);
                break;
            }
            Err(e) => {
                debug!("[中继桥接] Guest({}) 接受流失败: {}", remote_guest, e);
                break;
            }
        }
    }

    info!(
        "[中继桥接] Guest({}) ↔ Host({}) 结束",
        remote_guest, remote_host
    );
}

/// 转发两对 QUIC 流（全双工）
async fn relay_streams(
    mut recv_a: quinn::RecvStream,
    mut send_b: quinn::SendStream,
    mut recv_b: quinn::RecvStream,
    mut send_a: quinn::SendStream,
) {
    let a_to_b = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_a.read(&mut buf).await {
                Ok(Some(n)) => {
                    if send_b.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = send_b.finish();
    };

    let b_to_a = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_b.read(&mut buf).await {
                Ok(Some(n)) => {
                    if send_a.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = send_a.finish();
    };

    tokio::join!(a_to_b, b_to_a);
}

// ============================================================
// 证书辅助
// ============================================================

fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert = rcgen::generate_simple_self_signed(vec!["phantom-relay".to_string()])
        .map_err(|e| format!("生成证书失败: {}", e))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    Ok((cert_der, key_der))
}

// ============================================================
// 清理任务
// ============================================================

/// 启动定时清理过期 token 的任务
pub fn start_cleanup_task(registry: SharedRegistry) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let mut reg = registry.lock().await;
            reg.cleanup_expired().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_relay_roles() {
        assert_eq!(
            parse_quic_token_payload("host|room-token"),
            ("room-token".to_string(), RelayPeerRole::Host)
        );
        assert_eq!(
            parse_quic_token_payload("guest|guest-ticket"),
            ("guest-ticket".to_string(), RelayPeerRole::Guest)
        );
        assert_eq!(
            parse_quic_token_payload("room-token"),
            ("room-token".to_string(), RelayPeerRole::Unknown)
        );
    }

    #[test]
    fn accepts_only_pip1_business_streams() {
        assert!(is_pip1_stream(b"PIP1"));
        assert!(!is_pip1_stream(b"\0\0\x27\x15"));
        assert!(!is_pip1_stream(b"PIP2"));
    }
}
