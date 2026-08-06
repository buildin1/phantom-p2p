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

use crate::crypto::{ReplayWindow, SessionCrypto};
use crate::stats::StatsManager;
use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::Connection;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

const MAX_PACKET: usize = 65535;

/// 该对端的流量统计句柄。
///
/// 连接建立时才知道 user_id，且 Host 侧有可能拿不到映射，故为 Option。
pub type PeerStats = Option<(Arc<StatsManager>, String)>;

/// 入方向丢包率的结算窗口
const LOSS_WINDOW: Duration = Duration::from_secs(2);

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
    stats: PeerStats,
}

/// 基于 overlay 计数器空洞的**入方向**丢包测量。
///
/// 数据面从 TCP 代理迁到 TUN + DATAGRAM 之后，唯一还在上报的丢包口径是 QUIC
/// 的路径统计，而那测的是**出方向**。真正影响体验的"对端发来、我没收到"
/// 只能靠计数器空洞算——计数器是发送端在加密时打上的，中继换几段也不影响，
/// 天然是端到端、入方向的。
struct LossMeter {
    highest: u64,
    received: u64,
    window_start: u64,
    window_began: Instant,
    started: bool,
}

impl LossMeter {
    fn new(now: Instant) -> Self {
        Self {
            highest: 0,
            received: 0,
            window_start: 0,
            window_began: now,
            started: false,
        }
    }

    fn on_received(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.window_start = counter;
        }
        self.highest = self.highest.max(counter);
        self.received += 1;
    }

    /// 窗口到期则结算，返回丢包率（万分之一）
    fn poll(&mut self, now: Instant) -> Option<u16> {
        if !self.started || now.duration_since(self.window_began) < LOSS_WINDOW {
            return None;
        }
        let span = self.highest.saturating_sub(self.window_start) + 1;
        let received = self.received.min(span);
        let bp = if span == 0 {
            0
        } else {
            (((span - received).saturating_mul(10_000)) / span).min(10_000) as u16
        };
        self.window_start = self.highest + 1;
        self.received = 0;
        self.window_began = now;
        Some(bp)
    }
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
        let len = sealed.len();
        match self.conn.send_datagram(sealed.into()) {
            Ok(()) => {
                // 数据面迁到 DATAGRAM 之后，这个埋点一直没跟着迁过来，
                // 于是不管传多少数据带宽都显示 0。
                if let Some((stats, user)) = &self.stats {
                    let (stats, user) = (stats.clone(), user.clone());
                    tokio::spawn(async move { stats.record_send(&user, len).await });
                }
                true
            }
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
    /// 所有已接入的对端连接。
    ///
    /// 必须显式持有：收包任务循环在自己克隆的那份 `Connection` 上，
    /// 只丢掉 `Arc<TunBridge>` 是停不掉它的。不在关闭时逐个 `close()`，
    /// 就会出现"房间已关，隧道却还能用"。
    conns: Mutex<Vec<Connection>>,
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
        stats: PeerStats,
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
        bridge.attach_peer(quic_conn, crypto, None, stats).await?;
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
            conns: Mutex::new(Vec::new()),
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
        stats: PeerStats,
    ) -> Result<(), TunError> {
        let forwarder = PeerForwarder {
            conn: conn.clone(),
            crypto,
            stats,
        };
        tracing::info!(
            "[TUN] 数据报通道就绪 (local={}, peer_hint={:?}, host={}, max_datagram={:?})",
            self.my_vip,
            peer_hint,
            self.is_host,
            conn.max_datagram_size()
        );
        self.conns.lock().await.push(conn.clone());
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
        // 必须显式关掉每条连接。收包任务克隆了自己的连接句柄，光丢引用停不掉它，
        // 于是会出现"房间已关，旧会话却还能收发"。关掉之后 `read_datagram()`
        // 立刻返回错误，任务自然退出，对端也能收到断开通知。
        for conn in self.conns.lock().await.drain(..) {
            conn.close(0u32.into(), b"tunnel closed");
        }
        self.peers.lock().await.clear();
        *self.default_peer.lock().await = None;
        self.tun.close().await;
    }

    pub fn host_vip(&self) -> Ipv4Addr {
        self.host_vip
    }
    pub fn my_vip(&self) -> Ipv4Addr {
        self.my_vip
    }
}

/// 内层流标识，用于按流拆分重放窗口。
///
/// 重放窗口若按会话全局维护，隧道里一条突发流量（比如传文件）就会把窗口整体
/// 往前推，另一条几乎静默的流（比如游戏）延迟到达的**合法**包便会被判成
/// "已滑出窗口"丢弃。积累到心跳也被误伤时，整条隧道掉线重连——这正是
/// "遇到瞬时流量就掉线、日志提示包被丢弃"的成因。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: u8,
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
}

/// 从已解密的 IP 包里提取流标识。
///
/// 没有端口概念的协议（ICMP 等）端口取 0，相当于按（协议, 源, 目的）粗粒度
/// 共享一个窗口——这类流量速率很低，不会触发误杀。
fn flow_key(header: &Ipv4Header, packet: &[u8]) -> FlowKey {
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let (source_port, destination_port) = match header.protocol {
        6 | 17 if packet.len() >= header_len + 4 => (
            u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
            u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
        ),
        _ => (0, 0),
    };
    FlowKey {
        protocol: header.protocol,
        source: header.source_addr(),
        source_port,
        destination: header.destination_addr(),
        destination_port,
    }
}

/// 每个对端连接最多跟踪多少条流。
///
/// 防的是对端伪造海量五元组把内存吃光。正常场景（哪怕 BT 那种同时几百个
/// 对等连接）远用不到这个量级，触发上限只按 FIFO 淘汰最老的流。
const MAX_TRACKED_FLOWS: usize = 4096;

/// 按内层流拆分的重放检测表。只被单个收包任务顺序访问，无需加锁。
struct FlowReplayTable {
    windows: HashMap<FlowKey, ReplayWindow>,
    insertion_order: VecDeque<FlowKey>,
}

impl FlowReplayTable {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// 该流的这个计数器是否可接受；可接受时顺带记账。
    fn accept(&mut self, key: FlowKey, counter: u64) -> bool {
        if !self.windows.contains_key(&key) {
            if self.windows.len() >= MAX_TRACKED_FLOWS {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.windows.remove(&oldest);
                }
            }
            self.windows.insert(key, ReplayWindow::new());
            self.insertion_order.push_back(key);
        }
        let window = self.windows.get(&key).expect("刚插入过，一定存在");
        if !window.check(counter) {
            return false;
        }
        window.accept(counter);
        true
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
    let mut flows = FlowReplayTable::new();
    let mut loss = LossMeter::new(Instant::now());
    loop {
        let datagram = conn.read_datagram().await.map_err(|e| e.to_string())?;
        if let Some((stats, user)) = &sender.stats {
            let (stats, user, n) = (stats.clone(), user.clone(), datagram.len());
            tokio::spawn(async move { stats.record_receive(&user, n).await });
        }

        // 解密失败不是致命错误：可能是认证不通过或途中损坏。
        // 丢弃这一个包继续跑，绝不能因此中断整条隧道。
        let (counter, packet) = match sender.crypto.open(&datagram) {
            Ok(v) => v,
            Err(e) => {
                debug!("[TUN] 丢弃无法解密的数据报: {}", e);
                continue;
            }
        };
        // 计数器空洞就是入方向丢包，必须在重放判定**之前**记——
        // 重放判定会把重复包挡掉，放在后面就统计不到真实到达情况了。
        loss.on_received(counter);
        if let Some(bp) = loss.poll(Instant::now()) {
            if let Some((stats, user)) = &sender.stats {
                let (stats, user) = (stats.clone(), user.clone());
                tokio::spawn(async move { stats.update_inbound_loss(&user, bp).await });
            }
            if bp > 0 {
                tracing::info!("[TUN] 入方向丢包 {:.2}%", bp as f64 / 100.0);
            }
        }

        let len = packet.len();
        if !(20..=MAX_PACKET).contains(&len) {
            debug!("[TUN] 丢弃长度异常的包: {}", len);
            continue;
        }
        let Some(header) = Ipv4Header::from_bytes(&packet) else {
            continue;
        };
        // 重放判定按内层流拆分，必须在拿到明文之后做——五元组在解密前不可见。
        let key = flow_key(header, &packet);
        if !flows.accept(key, counter) {
            debug!("[TUN] 丢弃重复/过旧的 overlay 报文 (counter={counter})");
            continue;
        }
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

    fn key(port: u16) -> FlowKey {
        FlowKey {
            protocol: 17,
            source: Ipv4Addr::new(172, 16, 0, 1),
            source_port: port,
            destination: Ipv4Addr::new(172, 16, 0, 2),
            destination_port: 25565,
        }
    }

    /// 本次修复的核心承诺：一条流的突发不得把另一条安静流的包判成"过旧"。
    ///
    /// 窗口若按会话全局维护，突发流量会把窗口整体推过去，安静流延迟到达的
    /// 合法包就会被丢弃，积累到心跳被误伤时整条隧道掉线——这正是
    /// "遇到瞬时流量就掉线"的成因。
    #[test]
    fn a_burst_on_one_flow_must_not_evict_another() {
        let mut table = FlowReplayTable::new();
        let quiet = key(4000);
        let bursty = key(5000);

        // 安静流先发一个包（计数器较小）
        assert!(table.accept(quiet, 10));

        // 突发流把会话计数器推得很远——远超单个窗口宽度
        for c in 100..100_000u64 {
            table.accept(bursty, c);
        }

        // 安静流随后到达的包仍然必须被接受
        assert!(
            table.accept(quiet, 11),
            "突发流量不得让安静流的后续包被判成过旧"
        );
        // 它自己的重复包照样要拒
        assert!(!table.accept(quiet, 11), "同一条流内的重复仍要拒绝");
    }

    /// 跟踪的流数必须有上限，否则对端伪造海量五元组就能把内存吃光
    #[test]
    fn tracked_flows_are_bounded() {
        let mut table = FlowReplayTable::new();
        for port in 0..(MAX_TRACKED_FLOWS as u32 * 2) {
            table.accept(key(port as u16), port as u64);
        }
        assert!(table.windows.len() <= MAX_TRACKED_FLOWS);
    }

    /// 没有端口的协议（ICMP）落到同一个键，但不同协议之间必须分开
    #[test]
    fn flow_key_separates_protocols() {
        let icmp = FlowKey {
            protocol: 1,
            source_port: 0,
            destination_port: 0,
            ..key(0)
        };
        let udp = key(0);
        assert_ne!(icmp.protocol, udp.protocol);
        let mut table = FlowReplayTable::new();
        assert!(table.accept(icmp, 5));
        assert!(table.accept(udp, 5), "不同协议是不同的流，不该互相判重放");
    }

    /// 入方向丢包：计数器空洞就是丢的包
    #[test]
    fn loss_meter_measures_counter_gaps() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        // 0..100 只收到偶数，即丢一半
        for c in (0..100u64).step_by(2) {
            m.on_received(c);
        }
        let bp = m.poll(t + LOSS_WINDOW).expect("窗口到期应结算");
        assert!(
            (4800..=5100).contains(&bp),
            "丢一半应报 ~50%，实得 {}bp",
            bp
        );
    }

    #[test]
    fn loss_meter_reports_zero_on_clean_link() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        for c in 0..100u64 {
            m.on_received(c);
        }
        assert_eq!(m.poll(t + LOSS_WINDOW), Some(0));
    }

    /// 窗口没到期不该结算，否则样本太少、丢包率全是噪声
    #[test]
    fn loss_meter_waits_for_the_window() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        m.on_received(0);
        assert_eq!(m.poll(t), None);
    }

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
