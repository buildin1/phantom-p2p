//! TCP 隧道引擎 — 基于 QUIC
//!
//! 将本地 TCP 连接通过 QUIC 流隧穿到对端。
//! 支持 P2P 直连和中继模式（底层 QUIC 连接不同，上层逻辑一致）。

use crate::stats::StatsManager;
use crate::tun_bridge::TunBridge;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

// ============================================================
// P2P QUIC 配置（自签名证书）
// ============================================================

/// 生成自签名 TLS 证书，返回 (cert_der, key_der)
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert = rcgen::generate_simple_self_signed(vec!["phantom-p2p".to_string()])
        .map_err(|e| format!("生成证书失败: {}", e))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    Ok((cert_der, key_der))
}

/// 构建 QUIC 服务端配置（Host 侧）
pub fn build_server_config() -> Result<quinn::ServerConfig, String> {
    crate::ensure_rustls_crypto_provider()?;

    let (cert_der, key_der) = generate_self_signed_cert()?;
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("私钥格式错误: {}", e))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("TLS 配置失败: {}", e))?;

    server_crypto.alpn_protocols = vec![b"phantom-p2p".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    // Keep-Alive: 每 10 秒发送一次心跳，减少 DPC 中断频率，同时足以维持大多数 NAT 映射
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // 空闲超时: 60 秒无活动则断开
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.max_concurrent_bidi_streams(4096u32.into());

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("QUIC 服务配置失败: {}", e))?,
    ));
    server_config.transport_config(Arc::new(transport_config));
    Ok(server_config)
}

/// 构建 QUIC 客户端配置（Guest 侧，跳过证书验证）
pub fn build_client_config() -> Result<quinn::ClientConfig, String> {
    crate::ensure_rustls_crypto_provider()?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"phantom-p2p".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    // Keep-Alive: 每 10 秒发送一次心跳，减少 DPC 中断频率，同时足以维持大多数 NAT 映射
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // 空闲超时: 60 秒无活动则断开
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.max_concurrent_bidi_streams(4096u32.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| format!("QUIC 客户端配置失败: {}", e))?,
    ));
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

/// 构建中继 QUIC 客户端配置（ALPN: phantom-relay）
pub fn build_relay_client_config() -> Result<quinn::ClientConfig, String> {
    crate::ensure_rustls_crypto_provider()?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"phantom-relay".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    // Keep-Alive: 每 10 秒发送一次心跳，减少 DPC 中断频率，同时足以维持大多数 NAT 映射
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // 空闲超时: 60 秒无活动则断开
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.max_concurrent_bidi_streams(4096u32.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| format!("QUIC 中继客户端配置失败: {}", e))?,
    ));
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

/// 跳过证书验证（P2P 自签名场景）
#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================
// Host 侧：QUIC 服务端 → 本地 TCP
// ============================================================

/// 在打洞成功的 UDP socket 上启动 QUIC 服务端（Host 侧）
///
/// 每个 incoming QUIC stream → 读 2 字节端口头 → 连接到本地 TCP 目标端口 → 双向转发
pub async fn start_host_tunnel(
    quic_endpoint: quinn::Endpoint,
    stats_manager: Arc<StatsManager>,
    host_peer_addr_map: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    tun_bridge: Option<Arc<TunBridge>>,
) -> Result<(), String> {
    info!("[隧道-Host] 等待 QUIC 连接...");

    // `incoming.await`（完成握手）必须 spawn 到独立任务里，绝不能在这个循环里同步等待：
    // 之前的写法是 `let conn = incoming.await?` 直接写在 while 循环体内，任何一个连接
    // 的握手卡住（比如对端 NAT/防火墙把回包丢了），下一次 `accept()` 就永远排不上号，
    // 整个 Host 会卡死，后续所有新用户（包括跟这个卡住的连接完全无关的新房客）都无法
    // 建立 QUIC 连接。握手本身也补一个超时，避免卡住的任务无限期占着资源。
    while let Some(incoming) = quic_endpoint.accept().await {
        let stats_manager = stats_manager.clone();
        let host_peer_addr_map = host_peer_addr_map.clone();
        let tun_bridge = tun_bridge.clone();

        tokio::spawn(async move {
            let conn = match tokio::time::timeout(Duration::from_secs(15), incoming).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!("[隧道-Host] QUIC 连接失败: {}", e);
                    return;
                }
                Err(_) => {
                    warn!("[隧道-Host] QUIC 握手超时（15s），放弃该连接");
                    return;
                }
            };

            let remote = conn.remote_address();
            let remote_key = remote.to_string();
            let mapped_user_id = {
                let mut peer_map = host_peer_addr_map.lock().await;
                peer_map.remove(&remote_key)
            };
            if let Some(user_id) = &mapped_user_id {
                stats_manager
                    .add_connection(user_id.clone(), "p2p".to_string())
                    .await;
                spawn_quic_monitor(conn.clone(), stats_manager.clone(), user_id.clone());
            } else {
                warn!(
                    "[隧道-Host] 未找到 {} 对应的 peer_session_id 映射，统计将忽略该连接",
                    remote
                );
            }
            info!("[隧道-Host] QUIC 连接已建立: {}", remote);

            loop {
                match conn.accept_bi().await {
                    Ok((send, recv)) => {
                        debug!("[隧道-Host] 新 QUIC 流 from {}", remote);
                        let bridge = tun_bridge.clone();
                        tokio::spawn(async move {
                            let mut prefix = [0u8; 4];
                            let (mut send, mut recv) = (send, recv);
                            if recv.read_exact(&mut prefix).await.is_err() {
                                let _ = send.finish();
                                return;
                            }
                            if &prefix == b"PIP1" {
                                if let Some(bridge) = bridge {
                                    if let Err(error) = bridge.handle_peer_stream(send, recv).await
                                    {
                                        warn!("[TUN] Host PIP1 stream ended with error: {}", error);
                                    }
                                } else {
                                    warn!("[TUN] Host received PIP1 stream before TUN was ready");
                                    let _ = send.finish();
                                }
                            } else {
                                warn!("[TUN] rejected legacy port-proxy stream from {}", remote);
                                let _ = send.finish();
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!("[隧道-Host] 对端主动关闭连接: {}", remote);
                        break;
                    }
                    Err(e) => {
                        warn!("[隧道-Host] 接受流失败: {}", e);
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

/// Host 侧：单个 QUIC 流 ↔ 本地 TCP 连接 双向转发
/// 流头 2 字节为目标端口（大端），支持多端口动态路由
#[cfg(any())]
async fn host_stream_handler(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) {
    // 读取 2 字节端口头
    let mut port_buf = [0u8; 2];
    if quic_recv.read_exact(&mut port_buf).await.is_err() {
        let _ = quic_send.finish();
        return;
    }
    host_stream_handler_prefixed(
        quic_send,
        quic_recv,
        port_buf,
        Vec::new(),
        stats_manager,
        user_id,
    )
    .await;
}

#[cfg(any())]
async fn host_stream_handler_prefixed(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    port_buf: [u8; 2],
    initial_data: Vec<u8>,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) {
    let target_port = u16::from_be_bytes(port_buf);
    let target = format!("127.0.0.1:{}", target_port);
    let mut tcp = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            error!("[隧道-Host] 连接本地游戏 {} 失败: {}", target, e);
            let _ = quic_send.finish();
            return;
        }
    };

    debug!("[隧道-Host] TCP 连接 {} 已建立", target);

    let (mut tcp_read, mut tcp_write) = tcp.split();
    let stats_for_quic_to_tcp = stats_manager.clone();
    let user_for_quic_to_tcp = user_id.clone();
    let stats_for_tcp_to_quic = stats_manager;
    let user_for_tcp_to_quic = user_id;

    // 双向转发
    let quic_to_tcp = async {
        let mut buf = vec![0u8; 65536];
        if !initial_data.is_empty() && tcp_write.write_all(&initial_data).await.is_err() {
            return;
        }
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    stats_for_quic_to_tcp
                        .record_receive(&user_for_quic_to_tcp, n)
                        .await;
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    let tcp_to_quic = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    stats_for_tcp_to_quic
                        .record_send(&user_for_tcp_to_quic, n)
                        .await;
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = quic_send.finish();
    };

    tokio::join!(quic_to_tcp, tcp_to_quic);
    debug!("[隧道-Host] 流转发结束");
}

// ============================================================
// Guest 侧：本地 TCP → QUIC 客户端
// ============================================================

/// Guest 侧：监听本地端口，每个 TCP 连接 → QUIC 双向流 → Host
///
/// `target_port`：写入流头的目标端口（= Host 侧游戏端口）
/// 返回本地监听的端口号
#[cfg(any())]
pub async fn start_guest_tunnel(
    quic_conn: quinn::Connection,
    _local_port: u16,
    _target_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<u16, String> {
    spawn_quic_monitor(quic_conn, stats_manager, user_id);
    info!("[TUN] Guest transparent transport ready (no local TCP listener)");
    Ok(0)
}

#[cfg(any())]
pub async fn start_guest_tunnel_legacy_disabled(
    quic_conn: quinn::Connection,
    local_port: u16,
    target_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<u16, String> {
    spawn_quic_monitor(quic_conn, stats_manager, user_id);
    info!("[TUN] Guest transparent transport ready (no local TCP listener)");
    return Ok(0);
    #[allow(unreachable_code)]
    let bind_addr = format!("127.0.0.1:{}", local_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            warn!(
                "[隧道-Guest] 端口 {} 被占用，自动回退到随机端口",
                local_port
            );
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|fallback_err| {
                    format!(
                        "绑定本地端口 {} 失败且随机端口回退失败: {} / {}",
                        bind_addr, e, fallback_err
                    )
                })?
        }
        Err(e) => {
            return Err(format!("绑定本地端口 {} 失败: {}", bind_addr, e));
        }
    };

    let actual_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(local_port);

    info!("[隧道-Guest] 监听 127.0.0.1:{} (TCP→QUIC)", actual_port);
    spawn_quic_monitor(quic_conn.clone(), stats_manager.clone(), user_id.clone());

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    debug!("[隧道-Guest] 本地连接 from {}", peer_addr);
                    let conn = quic_conn.clone();
                    tokio::spawn(guest_stream_handler(
                        conn,
                        tcp_stream,
                        target_port,
                        stats_manager.clone(),
                        user_id.clone(),
                    ));
                }
                Err(e) => {
                    error!("[隧道-Guest] 接受 TCP 连接失败: {}", e);
                    break;
                }
            }
        }
    });

    Ok(actual_port)
}

/// Guest 侧：单个 TCP 连接 ↔ QUIC 流 双向转发
/// 流头写入 2 字节目标端口（大端），Host 侧据此路由到正确游戏端口
#[cfg(any())]
async fn guest_stream_handler(
    conn: quinn::Connection,
    mut tcp_stream: TcpStream,
    target_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) {
    let (mut quic_send, mut quic_recv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            error!("[隧道-Guest] 打开 QUIC 流失败: {}", e);
            return;
        }
    };

    // 写入 2 字节端口头，Host 侧通过它路由到对应游戏端口
    if quic_send
        .write_all(&target_port.to_be_bytes())
        .await
        .is_err()
    {
        let _ = quic_send.finish();
        return;
    }

    let (mut tcp_read, mut tcp_write) = tcp_stream.split();
    let stats_for_tcp_to_quic = stats_manager.clone();
    let user_for_tcp_to_quic = user_id.clone();
    let stats_for_quic_to_tcp = stats_manager;
    let user_for_quic_to_tcp = user_id;

    let tcp_to_quic = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    stats_for_tcp_to_quic
                        .record_send(&user_for_tcp_to_quic, n)
                        .await;
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = quic_send.finish();
    };

    let quic_to_tcp = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    stats_for_quic_to_tcp
                        .record_receive(&user_for_quic_to_tcp, n)
                        .await;
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    tokio::join!(tcp_to_quic, quic_to_tcp);
    debug!("[隧道-Guest] 流转发结束");
}

// ============================================================
// QUIC Endpoint 创建辅助
// ============================================================

/// 在已有的 UDP socket 上创建 Host QUIC Endpoint（P2P 模式）
pub fn create_host_endpoint(socket: std::net::UdpSocket) -> Result<quinn::Endpoint, String> {
    let server_config = build_server_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(|e| format!("创建 Host QUIC Endpoint 失败: {}", e))?;

    Ok(endpoint)
}

/// 创建 Guest QUIC Endpoint 并连接到 Host
pub async fn create_guest_connection(
    socket: std::net::UdpSocket,
    peer_addr: SocketAddr,
) -> Result<quinn::Connection, String> {
    let client_config = build_client_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| format!("创建 Guest QUIC Endpoint 失败: {}", e))?;

    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(peer_addr, "phantom-p2p")
        .map_err(|e| format!("QUIC 连接发起失败: {}", e))?
        .await
        .map_err(|e| format!("QUIC 连接建立失败: {}", e))?;

    info!("[隧道-Guest] QUIC 连接到 {} 成功", peer_addr);
    Ok(conn)
}

// ============================================================
// 中继模式 QUIC 连接
// ============================================================

/// Host 端连接到中继服务器（QUIC）
pub async fn connect_relay_quic_host(
    relay_addr: SocketAddr,
    token: String,
    stats_manager: Arc<StatsManager>,
    user_id: String,
    tun_bridge: Option<Arc<TunBridge>>,
) -> Result<quinn::Connection, String> {
    info!("[中继-Host] 连接到中继服务器 {}", relay_addr);

    // 创建新的 UDP socket
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP socket 失败: {}", e))?;

    let client_config = build_relay_client_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| format!("创建中继 Endpoint 失败: {}", e))?;

    endpoint.set_default_client_config(client_config);

    // 连接到中继服务器（30s 超时防止永久阻塞）
    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint
            .connect(relay_addr, "phantom-relay")
            .map_err(|e| format!("中继 QUIC 连接发起失败: {}", e))?,
    )
    .await
    .map_err(|_| "中继 QUIC 连接超时（30s）".to_string())?
    .map_err(|e| format!("中继 QUIC 连接建立失败: {}", e))?;

    info!("[中继-Host] QUIC 连接成功，发送 token");

    // 发送 token 到首个双向流
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("打开首流失败: {}", e))?;

    let relay_token = format!("host|{}", token);
    send.write_all(relay_token.as_bytes())
        .await
        .map_err(|e| format!("发送 token 失败: {}", e))?;
    send.finish()
        .map_err(|e| format!("关闭发送流失败: {}", e))?;

    // 等待配对确认（最多等待 90s，超时则认为对方未连入）
    let response = match tokio::time::timeout(Duration::from_secs(90), recv.read_to_end(16)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).to_string(),
        Ok(Ok(_)) => return Err("中继服务器关闭连接".into()),
        Ok(Err(e)) => return Err(format!("读取响应失败: {}", e)),
        Err(_) => return Err("等待配对超时（90s），对方未连入中继".to_string()),
    };

    if response != "OK" {
        return Err(format!("配对失败: {}", response));
    }

    info!("[中继-Host] 配对成功，启动转发");

    // 启动透明 PIP1 转发循环（类似 P2P Host，但从中继接收流）
    let loop_conn = conn.clone();
    tokio::spawn(async move {
        relay_host_pip1_loop(loop_conn, stats_manager, user_id, tun_bridge).await;
    });

    Ok(conn)
}

/// Guest 端连接到中继服务器（QUIC）
pub async fn connect_relay_quic_guest(
    relay_addr: SocketAddr,
    token: String,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<quinn::Connection, String> {
    info!("[中继-Guest] 连接到中继服务器 {}", relay_addr);

    // 创建新的 UDP socket
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP socket 失败: {}", e))?;

    let client_config = build_relay_client_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| format!("创建中继 Endpoint 失败: {}", e))?;

    endpoint.set_default_client_config(client_config);

    // 连接到中继服务器（30s 超时防止永久阻塞）
    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint
            .connect(relay_addr, "phantom-relay")
            .map_err(|e| format!("中继 QUIC 连接发起失败: {}", e))?,
    )
    .await
    .map_err(|_| "中继 QUIC 连接超时（30s）".to_string())?
    .map_err(|e| format!("中继 QUIC 连接建立失败: {}", e))?;

    info!("[中继-Guest] QUIC 连接成功，发送 token");

    // 发送 token
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("打开首流失败: {}", e))?;

    let relay_token = format!("guest|{}", token);
    send.write_all(relay_token.as_bytes())
        .await
        .map_err(|e| format!("发送 token 失败: {}", e))?;
    send.finish()
        .map_err(|e| format!("关闭发送流失败: {}", e))?;

    // 等待配对确认（最多等待 90s，超时则认为对方未连入）
    let response = match tokio::time::timeout(Duration::from_secs(90), recv.read_to_end(16)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).to_string(),
        Ok(Ok(_)) => return Err("中继服务器关闭连接".into()),
        Ok(Err(e)) => return Err(format!("读取响应失败: {}", e)),
        Err(_) => return Err("等待配对超时（90s），对方未连入中继".to_string()),
    };

    if response != "OK" {
        return Err(format!("配对失败: {}", response));
    }

    info!("[中继-Guest] 配对成功，等待透明 TUN 接管连接");
    spawn_quic_monitor(conn.clone(), stats_manager, user_id);
    Ok(conn)
}

/// 中继 Host 侧透明 PIP1 转发循环
async fn relay_host_pip1_loop(
    conn: quinn::Connection,
    stats_manager: Arc<StatsManager>,
    user_id: String,
    tun_bridge: Option<Arc<TunBridge>>,
) {
    spawn_quic_monitor(conn.clone(), stats_manager.clone(), user_id.clone());
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                debug!("[中继-Host] 新流");
                let bridge = tun_bridge.clone();
                tokio::spawn(async move {
                    let mut prefix = [0u8; 4];
                    let (mut send, mut recv) = (send, recv);
                    if recv.read_exact(&mut prefix).await.is_err() {
                        let _ = send.finish();
                    } else if &prefix == b"PIP1" {
                        if let Some(bridge) = bridge {
                            if let Err(error) = bridge.handle_peer_stream(send, recv).await {
                                warn!("[TUN] Relay Host PIP1 stream ended with error: {}", error);
                            }
                        } else {
                            warn!("[TUN] Relay Host received PIP1 stream before TUN was ready");
                            let _ = send.finish();
                        }
                    } else {
                        warn!("[TUN] Relay Host rejected legacy port-proxy stream");
                        let _ = send.finish();
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("[中继-Host] 连接关闭");
                break;
            }
            Err(e) => {
                warn!("[中继-Host] 接受流失败: {}", e);
                break;
            }
        }
    }
}

fn spawn_quic_monitor(conn: quinn::Connection, stats_manager: Arc<StatsManager>, user_id: String) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let rtt_ms = conn.rtt().as_millis().min(u64::MAX as u128) as u64;
            stats_manager.add_latency_sample(&user_id, rtt_ms).await;
            let conn_stats = conn.stats();
            stats_manager
                .update_quic_path_stats(
                    &user_id,
                    conn_stats.path.sent_packets,
                    conn_stats.path.lost_packets,
                )
                .await;
            debug!(
                "[QUIC] path={} rtt={}ms sent={} lost={} loss_rate={:.2}%",
                conn.remote_address(),
                rtt_ms,
                conn_stats.path.sent_packets,
                conn_stats.path.lost_packets,
                if conn_stats.path.sent_packets == 0 {
                    0.0
                } else {
                    (conn_stats.path.lost_packets as f64 * 100.0)
                        / conn_stats.path.sent_packets as f64
                }
            );
            if conn.close_reason().is_some() {
                break;
            }
        }
    });
}

// ============================================================
// TunnelConnManager — 支持静默中继升级的连接管理器
// ============================================================

use std::sync::atomic::{AtomicUsize, Ordering};

/// Guest 侧连接管理器
///
/// 用于在 P2P → 中继的静默升级：
/// - 内部持有当前活跃的 QUIC 连接（可热替换）
/// - 记录当前活跃的 TCP↔QUIC 流数量
/// - 当游戏断开（活跃流=0）时触发升级窗口
pub struct TunnelConnManager {
    /// 当前活跃连接（RwLock 支持热替换）
    conn: tokio::sync::RwLock<Option<quinn::Connection>>,
    /// 活跃 TCP↔QUIC 流计数
    pub active_streams: Arc<AtomicUsize>,
}

impl TunnelConnManager {
    /// 创建管理器，初始连接为 P2P 连接
    pub fn new(conn: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            conn: tokio::sync::RwLock::new(Some(conn)),
            active_streams: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// 获取当前连接（只读）
    pub async fn get_conn(&self) -> Option<quinn::Connection> {
        self.conn.read().await.clone()
    }

    /// 热替换连接（静默升级时调用）
    pub async fn upgrade(&self, new_conn: quinn::Connection) {
        let mut guard = self.conn.write().await;
        *guard = Some(new_conn);
        info!("[TunnelManager] 连接已热替换（静默升级完成）");
    }

    /// 关闭管理器（清除连接）
    pub async fn close(&self) {
        let mut guard = self.conn.write().await;
        *guard = None;
    }

    /// 当前活跃流数量
    pub fn active_count(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }
}

/// Guest 侧：受 TunnelConnManager 控制的 TCP→QUIC 隧道
///
/// 与 start_guest_tunnel 的区别：每个新 TCP 连接都从 manager 读取当前连接，
/// 升级后的新游戏连接会自动走新的中继连接。
/// `target_port`：写入流头的目标端口（= Host 侧游戏端口）
pub async fn start_guest_tunnel_managed(
    manager: Arc<TunnelConnManager>,
    _local_port: u16,
    _target_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<u16, String> {
    if let Some(conn) = manager.get_conn().await {
        spawn_quic_monitor(conn, stats_manager, user_id);
    }
    info!("[TUN] Guest transparent transport ready (no local TCP listener)");
    Ok(0)
}

#[cfg(any())]
pub async fn start_guest_tunnel_managed_legacy_disabled(
    manager: Arc<TunnelConnManager>,
    local_port: u16,
    target_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
) -> Result<u16, String> {
    if let Some(conn) = manager.get_conn().await {
        spawn_quic_monitor(conn, stats_manager, user_id);
    }
    info!("[TUN] Guest transparent transport ready (no local TCP listener)");
    return Ok(0);
    #[allow(unreachable_code)]
    use std::io::ErrorKind;
    use tokio::net::TcpListener;

    let bind_addr = format!("127.0.0.1:{}", local_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            warn!("[隧道-Guest] 端口 {} 被占用，回退随机端口", local_port);
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|fe| format!("绑定本地端口失败: {} / {}", e, fe))?
        }
        Err(e) => return Err(format!("绑定本地端口 {} 失败: {}", bind_addr, e)),
    };

    let actual_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(local_port);

    info!(
        "[隧道-Guest] 受管监听 127.0.0.1:{} (TCP→QUIC, 支持静默升级)",
        actual_port
    );

    // 监控初始连接
    if let Some(conn) = manager.get_conn().await {
        spawn_quic_monitor(conn, stats_manager.clone(), user_id.clone());
    }

    let stats_for_accept = stats_manager.clone();
    let user_for_accept = user_id.clone();
    let mgr_clone = manager.clone();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let conn = match mgr_clone.get_conn().await {
                        Some(c) => c,
                        None => {
                            info!("[隧道-Guest] 管理器已关闭，停止接受新连接");
                            break;
                        }
                    };

                    debug!("[隧道-Guest] 新 TCP 连接 from {}", peer_addr);
                    let active = mgr_clone.active_streams.clone();
                    active.fetch_add(1, Ordering::Relaxed);

                    let stats_c = stats_for_accept.clone();
                    let user_c = user_for_accept.clone();

                    tokio::spawn(async move {
                        guest_stream_handler(conn, tcp_stream, target_port, stats_c, user_c).await;
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("[隧道-Guest] 接受 TCP 连接失败: {}", e);
                    break;
                }
            }
        }
    });

    Ok(actual_port)
}

/// 仅连接到中继服务器并完成配对握手，返回 QUIC 连接（不启动隧道循环）
/// 用于静默升级预连接中继。
pub async fn preconnect_relay_quic_guest(
    relay_addr: SocketAddr,
    token: String,
) -> Result<quinn::Connection, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP socket 失败: {}", e))?;

    let client_config = build_relay_client_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| format!("创建中继 Endpoint 失败: {}", e))?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint
            .connect(relay_addr, "phantom-relay")
            .map_err(|e| format!("中继 QUIC 连接发起失败: {}", e))?,
    )
    .await
    .map_err(|_| "中继 QUIC 连接超时（30s）".to_string())?
    .map_err(|e| format!("中继 QUIC 连接建立失败: {}", e))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("打开首流失败: {}", e))?;

    let relay_token = format!("guest|{}", token);
    send.write_all(relay_token.as_bytes())
        .await
        .map_err(|e| format!("发送 token 失败: {}", e))?;
    send.finish()
        .map_err(|e| format!("关闭发送流失败: {}", e))?;

    let response = match tokio::time::timeout(Duration::from_secs(90), recv.read_to_end(16)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).to_string(),
        Ok(Ok(_)) => return Err("中继服务器关闭连接".into()),
        Ok(Err(e)) => return Err(format!("读取响应失败: {}", e)),
        Err(_) => return Err("等待配对超时（90s）".to_string()),
    };

    if response != "OK" {
        return Err(format!("中继配对失败: {}", response));
    }

    info!("[中继预连] Guest 中继连接已就绪（待升级激活）");
    Ok(conn)
}

/// 仅连接 Host 到中继服务器并完成配对握手（不启动转发循环）
/// 用于后台预连接中继。
pub async fn preconnect_relay_quic_host(
    relay_addr: SocketAddr,
    token: String,
) -> Result<quinn::Connection, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP socket 失败: {}", e))?;

    let client_config = build_relay_client_config()?;
    let runtime = quinn::default_runtime().ok_or("无法获取 quinn 运行时")?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| format!("创建中继 Endpoint 失败: {}", e))?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint
            .connect(relay_addr, "phantom-relay")
            .map_err(|e| format!("中继 QUIC 连接发起失败: {}", e))?,
    )
    .await
    .map_err(|_| "中继 QUIC 连接超时（30s）".to_string())?
    .map_err(|e| format!("中继 QUIC 连接建立失败: {}", e))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("打开首流失败: {}", e))?;

    let relay_token = format!("host|{}", token);
    send.write_all(relay_token.as_bytes())
        .await
        .map_err(|e| format!("发送 token 失败: {}", e))?;
    send.finish()
        .map_err(|e| format!("关闭发送流失败: {}", e))?;

    let response = match tokio::time::timeout(Duration::from_secs(90), recv.read_to_end(16)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).to_string(),
        Ok(Ok(_)) => return Err("中继服务器关闭连接".into()),
        Ok(Err(e)) => return Err(format!("读取响应失败: {}", e)),
        Err(_) => return Err("等待配对超时（90s）".to_string()),
    };

    if response != "OK" {
        return Err(format!("中继配对失败: {}", response));
    }

    info!("[中继预连] Host 中继连接已就绪（待升级激活）");
    Ok(conn)
}

/// 高级模式 Guest 端精确端口隧道
///
/// 与 start_guest_tunnel_managed 的区别：
/// - 严格绑定指定端口，**不随机回退**（端口对等映射要求）
/// - 成功后通过 on_ready 回调通知调用方（通常用于向前端发射事件）
#[cfg(any())]
pub async fn start_port_tunnel_exact(
    manager: Arc<TunnelConnManager>,
    local_port: u16,
    stats_manager: Arc<StatsManager>,
    user_id: String,
    on_ready: impl FnOnce(u16) + Send + 'static,
) -> Result<u16, String> {
    return Err("legacy port proxy is disabled; transparent TUN is mandatory".to_string());
    #[allow(unreachable_code)]
    use tokio::net::TcpListener;

    let bind_addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("精确绑定端口 {} 失败（端口已被占用）: {}", local_port, e))?;

    let actual_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(local_port);

    info!(
        "[高级隧道] 精确绑定 127.0.0.1:{} (端口对等映射)",
        actual_port
    );

    // 通知调用方端口已就绪
    on_ready(actual_port);

    let stats_for_accept = stats_manager.clone();
    let user_for_accept = user_id.clone();
    let mgr_clone = manager.clone();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let conn = match mgr_clone.get_conn().await {
                        Some(c) => c,
                        None => {
                            info!(
                                "[高级隧道] 管理器已关闭，停止接受新连接 (port {})",
                                actual_port
                            );
                            break;
                        }
                    };

                    debug!(
                        "[高级隧道] 新 TCP 连接 from {} on port {}",
                        peer_addr, actual_port
                    );
                    let active = mgr_clone.active_streams.clone();
                    active.fetch_add(1, Ordering::Relaxed);

                    let stats_c = stats_for_accept.clone();
                    let user_c = user_for_accept.clone();

                    tokio::spawn(async move {
                        guest_stream_handler(conn, tcp_stream, actual_port, stats_c, user_c).await;
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("[高级隧道] 接受 TCP 连接失败 (port {}): {}", actual_port, e);
                    break;
                }
            }
        }
    });

    Ok(actual_port)
}
