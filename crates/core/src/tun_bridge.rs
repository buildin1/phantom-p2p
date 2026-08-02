//! Virtual L3 overlay over QUIC **datagrams**.
//!
//! The bridge transports complete IPv4 packets. TCP state, UDP state and
//! checksums therefore remain the responsibility of the host OS instead of
//! being reimplemented in an application-level port proxy.
//!
//! 传输语义是 **不可靠、无序的数据报**（RFC 9221），不是可靠有序流。
//! 三层隧道用可靠流是错的：一个丢包会阻塞后续所有流量、
//! 过期的实时包仍被重传、内层 TCP 与外层重传叠加会导致吞吐崩塌。
//! 内层协议自己负责可靠性——TCP 本就会重传，UDP 本就允许丢。

use crate::crypto::SessionCrypto;
use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::Connection;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const MAX_PACKET: usize = 65535;

/// TUN 设备 MTU。
///
/// 必须留出 QUIC DATAGRAM 的空间：QUIC 为避免 IP 分片会把数据报限制在
/// 保守的路径 MTU（典型 ~1200 字节）以内，还要再扣掉 overlay 加密的
/// [`crate::crypto::OVERHEAD`]（8 字节计数器 + 16 字节认证标签）。
///
/// `1200 - 24 = 1176`，向下取整留一点余量。**不能直接取 1200**——
/// 那样每个满载包加密后都会超限被拒发，而这种故障只在真实链路上才暴露，
/// 本地环回测不出来。`full_mtu_packet_still_fits_in_a_quic_datagram` 用断言钉死了这个关系。
pub const TUN_MTU: u16 = 1160;

/// 一个对端的转发句柄。
///
/// 数据面走 **QUIC DATAGRAM**（RFC 9221）而非可靠有序流。对三层隧道而言
/// 可靠流是错的：一个丢包会阻塞后续**所有**流量（队头阻塞）；
/// 迟到 200ms 的实时包早已无用却仍被重传；内层 TCP 叠加外层重传更会
/// 让退避相互作用、吞吐崩塌。
///
/// 附带的结构性好处：`send_datagram` 是**同步非阻塞**的，
/// 要么入队要么立刻报错，不会像 `write_all` 那样被拥塞卡住。
/// 因此原先"每对端一条 channel + 专用任务 + 写超时"的整套机制不再需要——
/// 那套机制本就是为了绕开流写入会阻塞 TUN 读循环的问题。
#[derive(Clone)]
struct PeerForwarder {
    conn: Connection,
    /// overlay 端到端加密。中继模式下 QUIC 是逐跳的，中继能看到明文，
    /// 机密性必须由这一层保证。
    crypto: Arc<SessionCrypto>,
}

impl PeerForwarder {
    /// 加密并投递一个 IP 包。永不阻塞调用方。
    fn try_forward(&self, packet: &[u8]) -> bool {
        let sealed = match self.crypto.seal(packet) {
            Ok(v) => v,
            Err(e) => {
                warn!("[TUN] overlay 加密失败: {}", e);
                return false;
            }
        };
        // 超出对端通告的数据报上限时直接拒发——发出去也会被丢，
        // 而且这说明 TUN_MTU 相对当前路径设得过大，值得记一笔。
        if let Some(limit) = self.conn.max_datagram_size() {
            if sealed.len() > limit {
                warn!(
                    "[TUN] 包过大无法作为数据报发送: {} > {}（考虑下调 TUN MTU）",
                    sealed.len(),
                    limit
                );
                return false;
            }
        }
        match self.conn.send_datagram(sealed.into()) {
            Ok(()) => true,
            Err(e) => {
                debug!("[TUN] 数据报发送失败: {}", e);
                false
            }
        }
    }
}

type PeerSenders = Arc<Mutex<HashMap<Ipv4Addr, PeerForwarder>>>;

pub struct TunBridge {
    tun: Arc<TunDevice>,
    host_vip: Ipv4Addr,
    my_vip: Ipv4Addr,
    guest_network: Ipv4Addr,
    is_host: bool,
    peers: PeerSenders,
    default_peer: Mutex<Option<PeerForwarder>>,
    closed: std::sync::atomic::AtomicBool,
    tx_packets: AtomicU64,
}

impl TunBridge {
    /// Create a bridge and attach one QUIC connection. Guest uses this form;
    /// Host may use it for the first peer and attach additional peers later.
    pub async fn start(
        subnet_prefix: &str,
        virtual_ip: &str,
        host_virtual_ip: &str,
        quic_conn: Connection,
        crypto: Arc<SessionCrypto>,
    ) -> Result<Arc<Self>, TunError> {
        let my_ip: Ipv4Addr = virtual_ip
            .parse()
            .map_err(|_| TunError::CreateFailed(format!("invalid virtual IP {}", virtual_ip)))?;
        let host_ip: Ipv4Addr = host_virtual_ip.parse().map_err(|_| {
            TunError::CreateFailed(format!("invalid Host virtual IP {}", host_virtual_ip))
        })?;
        let guest_network = parse_network(subnet_prefix)?;
        if !same_prefix24(my_ip, guest_network) {
            return Err(TunError::CreateFailed(
                "virtual IP is outside the assigned subnet".into(),
            ));
        }
        let tun_name = adapter_name(my_ip);
        let tun =
            TunDevice::create(&tun_name, my_ip, Ipv4Addr::new(255, 255, 255, 0), TUN_MTU).await?;
        if !same_prefix24(host_ip, guest_network) {
            tun.add_route(host_ip, 32).await?;
        }
        let bridge = Self::from_tun(tun, host_ip, my_ip, guest_network, false);
        bridge.attach_peer(quic_conn, crypto, None).await?;
        Ok(bridge)
    }

    /// Create a Host bridge before any peer connection exists.
    pub async fn start_host(subnet_prefix: &str, virtual_ip: &str) -> Result<Arc<Self>, TunError> {
        let guest_network = parse_network(subnet_prefix)?;
        let my_ip: Ipv4Addr = virtual_ip.parse().map_err(|_| {
            TunError::CreateFailed(format!("invalid Host virtual IP {}", virtual_ip))
        })?;
        let fixed_host = !same_prefix24(my_ip, guest_network);
        let tun_name = adapter_name(my_ip);
        let netmask = if fixed_host {
            Ipv4Addr::new(255, 255, 255, 255)
        } else {
            Ipv4Addr::new(255, 255, 255, 0)
        };
        let tun = TunDevice::create(&tun_name, my_ip, netmask, TUN_MTU).await?;
        if fixed_host {
            tun.add_route(guest_network, 24).await?;
        }
        Ok(Self::from_tun(tun, my_ip, my_ip, guest_network, true))
    }

    fn from_tun(
        tun: TunDevice,
        host_vip: Ipv4Addr,
        my_vip: Ipv4Addr,
        guest_network: Ipv4Addr,
        is_host: bool,
    ) -> Arc<Self> {
        let bridge = Arc::new(Self {
            tun: Arc::new(tun),
            host_vip,
            my_vip,
            guest_network,
            is_host,
            peers: Arc::new(Mutex::new(HashMap::new())),
            default_peer: Mutex::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
        });
        let reader = bridge.clone();
        tokio::spawn(async move {
            reader.tun_read_loop().await;
        });
        bridge
    }

    /// 接入一个对端的 QUIC 连接。
    ///
    /// `crypto` 是与该对端协商好的 overlay 会话密钥；
    /// `peer_hint` 在首包揭示对端虚拟源地址之前用于路由。
    pub async fn attach_peer(
        &self,
        conn: Connection,
        crypto: Arc<SessionCrypto>,
        peer_hint: Option<Ipv4Addr>,
    ) -> Result<(), TunError> {
        let forwarder = PeerForwarder {
            conn: conn.clone(),
            crypto,
        };
        tracing::info!(
            "[TUN] 数据报通道就绪 (local={}, peer_hint={:?}, host={}, max_datagram={:?})",
            self.my_vip,
            peer_hint,
            self.is_host,
            conn.max_datagram_size()
        );
        if let Some(ip) = peer_hint {
            self.peers.lock().await.insert(ip, forwarder.clone());
        }
        let mut default = self.default_peer.lock().await;
        if !self.is_host && default.is_none() {
            *default = Some(forwarder.clone());
        }
        drop(default);

        let tun = self.tun.clone();
        let peers = self.peers.clone();
        let sender = forwarder;
        let is_host = self.is_host;
        let host_vip = self.host_vip;
        let guest_network = self.guest_network;
        tokio::spawn(async move {
            if let Err(e) =
                receive_datagrams(conn, tun, peers, sender, is_host, host_vip, guest_network).await
            {
                debug!("[TUN] 对端数据报循环结束: {}", e);
            }
        });
        Ok(())
    }

    async fn tun_read_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_PACKET];
        while !self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            let n = match self.tun.read_packet(&mut buf).await {
                Ok(n) if n >= 20 => n,
                Ok(_) => continue,
                Err(e) => {
                    warn!("[TUN] read failed: {}", e);
                    break;
                }
            };
            let Some(header) = Ipv4Header::from_bytes(&buf[..n]) else {
                continue;
            };
            let dst = header.destination_addr();
            let src = header.source_addr();
            if src != self.my_vip {
                warn!(
                    "[TUN] dropped packet with non-overlay source {} -> {} (expected {})",
                    src, dst, self.my_vip
                );
                continue;
            }
            let sender = {
                let peers = self.peers.lock().await;
                peers.get(&dst).cloned()
            };
            let sender = match sender {
                Some(sender) => Some(sender),
                None if !self.is_host => self.default_peer.lock().await.clone(),
                None => None,
            };
            if let Some(sender) = sender {
                // Handing off to the peer's dedicated forwarder task keeps
                // this loop non-blocking: the actual (possibly slow) QUIC
                // write happens elsewhere, under its own timeout, so a
                // single wedged peer can no longer starve every other peer
                // sharing this bridge.
                if sender.try_forward(&buf[..n]) {
                    let count = self.tx_packets.fetch_add(1, Ordering::Relaxed) + 1;
                    if count <= 100 || count % 1000 == 0 {
                        tracing::info!(
                            "[TUN] tx #{} {} -> {} {} bytes={}",
                            count,
                            src,
                            dst,
                            packet_protocol(&buf[..n]),
                            n
                        );
                    }
                } else {
                    warn!(
                        "[TUN] peer forward queue rejected packet {} -> {} ({} bytes)",
                        src, dst, n
                    );
                }
            } else {
                warn!(
                    "[TUN] no peer route for {} -> {} ({} bytes, host={})",
                    src, dst, n, self.is_host
                );
            }
        }
    }

    pub async fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.tun.close().await;
    }

    pub fn host_vip(&self) -> Ipv4Addr {
        self.host_vip
    }
    pub fn my_vip(&self) -> Ipv4Addr {
        self.my_vip
    }
}

/// 接收对端数据报，解密后写入 TUN。
///
/// 与旧的流式实现相比，这里**丢包不影响后续包**——数据报之间彼此独立，
/// 不存在队头阻塞，也不会为早已过期的实时流量做重传。
/// 单个包解密失败只丢它自己，循环继续。
async fn receive_datagrams(
    conn: Connection,
    tun: Arc<TunDevice>,
    peers: PeerSenders,
    sender: PeerForwarder,
    is_host: bool,
    host_vip: Ipv4Addr,
    guest_network: Ipv4Addr,
) -> Result<(), String> {
    loop {
        let datagram = conn.read_datagram().await.map_err(|e| e.to_string())?;

        // 解密失败不是致命错误：可能是重放、乱序过旧、或途中损坏。
        // 丢弃这一个包继续跑，绝不能因此中断整条隧道。
        let packet = match sender.crypto.open(&datagram) {
            Ok(p) => p,
            Err(e) => {
                debug!("[TUN] 丢弃无法解密的数据报: {}", e);
                continue;
            }
        };
        let len = packet.len();
        if !(20..=MAX_PACKET).contains(&len) {
            debug!("[TUN] 丢弃长度异常的包: {}", len);
            continue;
        }
        let Some(header) = Ipv4Header::from_bytes(&packet) else {
            continue;
        };
        let source = header.source_addr();
        let valid_source = if is_host {
            source != host_vip && same_prefix24(source, guest_network)
        } else {
            source == host_vip
        };
        if !valid_source {
            warn!(
                "[TUN] rejected virtual packet source {} (host={}, expected host={})",
                source, is_host, host_vip
            );
            continue;
        }
        // A virtual IP may be reused after a Guest reconnects or switches
        // transport. Always let the newest authenticated stream own the route;
        // retaining the first sender would black-hole replies into a closed
        // QUIC connection.
        peers.lock().await.insert(source, sender.clone());
        tun.write_packet(&packet).await.map_err(|e| {
            format!(
                "Wintun write {} -> {} ({} bytes): {}",
                source,
                header.destination_addr(),
                len,
                e
            )
        })?;
        let count = tun_rx_counter(&tun, &peers, &sender, is_host);
        if count <= 100 || count % 1000 == 0 {
            tracing::info!(
                "[TUN] rx #{} {} -> {} {} bytes={}",
                count,
                source,
                header.destination_addr(),
                packet_protocol(&packet),
                len
            );
        }
    }
}

fn packet_protocol(packet: &[u8]) -> String {
    let Some(header) = Ipv4Header::from_bytes(packet) else {
        return "invalid-ipv4".to_string();
    };
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    match header.protocol {
        6 if packet.len() >= header_len + 20 => {
            let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            let flags = packet[header_len + 13];
            format!("tcp {}->{} flags=0x{:02x}", src_port, dst_port, flags)
        }
        17 if packet.len() >= header_len + 8 => {
            let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            format!("udp {}->{}", src_port, dst_port)
        }
        protocol => format!("proto={}", protocol),
    }
}

// Kept separate from packet routing so the receive path remains allocation-free.
fn tun_rx_counter(
    _tun: &Arc<TunDevice>,
    _peers: &PeerSenders,
    _sender: &PeerForwarder,
    _is_host: bool,
) -> u64 {
    // receive_frames is shared by host and guest and predates per-bridge state;
    // the log counter is process-local and only used for diagnostics.
    static COUNT: AtomicU64 = AtomicU64::new(0);
    COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

fn parse_network(prefix: &str) -> Result<Ipv4Addr, TunError> {
    let ip: Ipv4Addr = format!("{}.0", prefix)
        .parse()
        .map_err(|_| TunError::CreateFailed(format!("invalid virtual subnet {}", prefix)))?;
    Ok(ip)
}

fn same_prefix24(ip: Ipv4Addr, network: Ipv4Addr) -> bool {
    ip.octets()[..3] == network.octets()[..3]
}

fn adapter_name(ip: Ipv4Addr) -> String {
    // Linux IFNAMSIZ limits interface names to 15 characters. Keep all four
    // octets so simultaneous rooms cannot collide while staying portable.
    #[cfg(target_os = "linux")]
    {
        let [a, b, c, d] = ip.octets();
        return format!("pp2-{}-{}-{}-{}", a, b, c, d);
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("PhantomP2P-{}", ip.to_string().replace('.', "-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_name_is_unique_per_virtual_ip() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(adapter_name(Ipv4Addr::new(172, 16, 1, 1)), "pp2-172-16-1-1");
            assert!(adapter_name(Ipv4Addr::new(172, 16, 1, 1)).len() <= 15);
            assert_ne!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 1)),
                adapter_name(Ipv4Addr::new(172, 16, 1, 2))
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 1)),
                "PhantomP2P-172-16-1-1"
            );
            assert_eq!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 2)),
                "PhantomP2P-172-16-1-2"
            );
        }
    }

    #[test]
    fn fixed_host_is_outside_dynamic_guest_subnet() {
        let guest_network = parse_network("172.16.8").unwrap();
        assert!(same_prefix24(Ipv4Addr::new(172, 16, 8, 1), guest_network));
        assert!(!same_prefix24(Ipv4Addr::new(172, 24, 0, 1), guest_network));
    }

    /// 一个满 MTU 的包加上 overlay 加密开销后，必须仍能塞进 QUIC 数据报。
    ///
    /// QUIC 为避免 IP 分片会把数据报限制在保守的路径 MTU 内（典型 1200 左右）。
    /// 这个关系一旦破坏，**每一个满载包都会被拒发**——而且只在真实链路上
    /// 才暴露，本地环回测不出来，所以在这里用断言钉死。
    #[test]
    fn full_mtu_packet_still_fits_in_a_quic_datagram() {
        // QUIC 在 IPv6 最小 MTU(1280) 下扣掉包头后的保守可用值
        const CONSERVATIVE_QUIC_DATAGRAM_LIMIT: usize = 1200;
        let worst_case = TUN_MTU as usize + crate::crypto::OVERHEAD;
        assert!(
            worst_case <= CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            "TUN_MTU({}) + 加密开销({}) = {} 超出 QUIC 数据报保守上限 {}",
            TUN_MTU,
            crate::crypto::OVERHEAD,
            worst_case,
            CONSERVATIVE_QUIC_DATAGRAM_LIMIT
        );
    }

    /// MTU 也不能定得过小，否则每个 IP 包都要被内层协议分片，白白浪费带宽
    #[test]
    fn tun_mtu_is_large_enough_to_be_useful() {
        assert!(
            TUN_MTU >= 1000,
            "MTU {} 过小会导致大量分片，严重拖累吞吐",
            TUN_MTU
        );
    }
}
