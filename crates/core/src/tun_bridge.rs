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
use crate::fec::{self, FecDecoder, FecEncoder, Incoming, LossTracker, RedundancyController};
use crate::stats::StatsManager;
use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::Connection;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const MAX_PACKET: usize = 65535;

/// 该对端的统计上报句柄（连接建立时才知道 user_id，故为 Option）
pub type PeerStats = Option<(Arc<StatsManager>, String)>;

/// TUN 设备 MTU。
///
/// 必须留出 QUIC DATAGRAM 的空间：QUIC 为避免 IP 分片会把数据报限制在
/// 保守的路径 MTU（典型 ~1200 字节）以内，还要再扣掉两层开销：
/// - overlay 加密 [`crate::crypto::OVERHEAD`]（8 字节计数器 + 16 字节认证标签）
/// - FEC 头（数据报 5 字节；校验报 9 字节 + 2 字节长度前缀，是最紧的那一档）
///
/// 最坏情况是**校验报**：`TUN_MTU + OVERHEAD + LEN_PREFIX + PARITY_HEADER_LEN`。
/// 取 1140 时为 `1140 + 24 + 2 + 9 = 1175`，距 1200 还有 25 字节余量。
///
/// **不能直接取 1200**——那样每个满载包加密后都会超限被拒发，
/// 而这种故障只在真实链路上才暴露，本地环回测不出来。
/// `full_mtu_packet_still_fits_in_a_quic_datagram` 用断言钉死了这个关系。
pub const TUN_MTU: u16 = 1140;

/// 分组 flush 巡检间隔。稀疏流量时组攒不满，靠这个巡检按时关组补 parity。
const FLUSH_TICK: std::time::Duration = std::time::Duration::from_millis(5);

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
/// 一个对端的 FEC 会话状态。
///
/// `peer_supports_fec` 由**带内探测**得出（收到对端 HELLO 才置位），
/// 而不是靠信令协商——见 [`crate::fec`] 模块文档。这样做是失败安全的：
/// 任何一环出问题都只退回传统格式，而不会把对端看不懂的报文发出去把隧道搞断。
struct FecSession {
    peer_supports_fec: AtomicBool,
    encoder: std::sync::Mutex<FecEncoder>,
    controller: std::sync::Mutex<RedundancyController>,
    /// 本地发送失败计数。用于区分「网络丢包」与「本地发送队列丢包」——
    /// 后者是拥塞控制把窗口压崩导致的，FEC 完全帮不上忙，得靠调 CC 解决。
    send_failures: AtomicU64,
    parity_sent: AtomicU64,
    recovered: AtomicU64,
}

impl FecSession {
    fn new() -> Self {
        Self {
            peer_supports_fec: AtomicBool::new(false),
            encoder: std::sync::Mutex::new(FecEncoder::new()),
            controller: std::sync::Mutex::new(RedundancyController::new(0)),
            send_failures: AtomicU64::new(0),
            parity_sent: AtomicU64::new(0),
            recovered: AtomicU64::new(0),
        }
    }

    fn peer_ready(&self) -> bool {
        self.peer_supports_fec.load(Ordering::Relaxed)
    }

    /// 首次得知对端支持 FEC 时返回 true（用于只打一次日志）
    fn mark_peer_ready(&self) -> bool {
        !self.peer_supports_fec.swap(true, Ordering::Relaxed)
    }
}

#[derive(Clone)]
struct PeerForwarder {
    conn: Connection,
    /// overlay 端到端加密。中继模式下 QUIC 是逐跳的，中继能看到明文，
    /// 机密性必须由这一层保证。
    crypto: Arc<SessionCrypto>,
    fec: Arc<FecSession>,
    stats: PeerStats,
}

impl PeerForwarder {
    /// 把一个已经封装好的数据报投递出去。永不阻塞调用方。
    fn send_raw(&self, datagram: Vec<u8>) -> bool {
        // 超出对端通告的数据报上限时直接拒发——发出去也会被丢，
        // 而且这说明 TUN_MTU 相对当前路径设得过大，值得记一笔。
        if let Some(limit) = self.conn.max_datagram_size() {
            if datagram.len() > limit {
                warn!(
                    "[TUN] 包过大无法作为数据报发送: {} > {}（考虑下调 TUN MTU）",
                    datagram.len(),
                    limit
                );
                return false;
            }
        }
        let len = datagram.len();
        match self.conn.send_datagram(datagram.into()) {
            Ok(()) => {
                if let Some((stats, user)) = &self.stats {
                    let (stats, user) = (stats.clone(), user.clone());
                    tokio::spawn(async move { stats.record_send(&user, len).await });
                }
                true
            }
            Err(e) => {
                // 这里的失败发生在**本机**，包根本没上过网络。
                // 与网络丢包是两回事，必须分开计数，否则会误判病因。
                let n = self.fec.send_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 10 || n % 500 == 0 {
                    warn!(
                        "[TUN] 本地数据报发送失败 #{}（非网络丢包，通常是拥塞窗口耗尽）: {}",
                        n, e
                    );
                }
                false
            }
        }
    }

    /// 加密并投递一个 IP 包。永不阻塞调用方。
    fn try_forward(&self, packet: &[u8]) -> bool {
        let sealed = match self.crypto.seal(packet) {
            Ok(v) => v,
            Err(e) => {
                warn!("[TUN] overlay 加密失败: {}", e);
                return false;
            }
        };
        // 对端不支持 FEC（旧版本）就走传统格式，保证互通
        if !self.fec.peer_ready() {
            return self.send_raw(sealed);
        }

        let now = Instant::now();
        let (data, parities) = {
            let mut enc = self.fec.encoder.lock().unwrap_or_else(|e| e.into_inner());
            let data = enc.push(&sealed, now);
            let parities = if enc.should_close(now) {
                enc.close_group()
            } else {
                Vec::new()
            };
            (data, parities)
        };
        // 数据报立即发出，绝不为了攒组而缓冲——FEC 对正常路径零延迟惩罚
        let ok = self.send_raw(data);
        for p in parities {
            self.fec.parity_sent.fetch_add(1, Ordering::Relaxed);
            self.send_raw(p);
        }
        ok
    }

    /// 定时巡检：稀疏流量时组攒不满，靠这里按时关组补 parity
    fn flush_due(&self, now: Instant) {
        if !self.fec.peer_ready() {
            return;
        }
        let parities = {
            let mut enc = self.fec.encoder.lock().unwrap_or_else(|e| e.into_inner());
            if !enc.should_close(now) {
                return;
            }
            enc.close_group()
        };
        for p in parities {
            self.fec.parity_sent.fetch_add(1, Ordering::Relaxed);
            self.send_raw(p);
        }
    }

    /// 把控制器当前档位同步给编码器
    fn sync_redundancy(&self) {
        let level = {
            let c = self
                .fec
                .controller
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            c.current()
        };
        let mut enc = self.fec.encoder.lock().unwrap_or_else(|e| e.into_inner());
        enc.set_redundancy(level);
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
            fec: Arc::new(FecSession::new()),
            stats,
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

        // 稀疏流量时分组攒不满，需要独立巡检按时关组补 parity。
        // 随连接结束自动退出，不会留下孤儿任务。
        let flusher = forwarder.clone();
        let flush_conn = conn.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_TICK);
            loop {
                tick.tick().await;
                if flush_conn.close_reason().is_some() {
                    break;
                }
                flusher.flush_due(Instant::now());
            }
        });

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

/// 内层流标识，用于按流拆分重放检测窗口。
///
/// `overlay 报文重放或过旧` 的重放窗口曾经是整条隧道会话共享一个：
/// 隧道里混跑着多条互不相关的流量时（比如同时有人在下 BT、也有人在
/// 手动 ping），一条流的突发会把共享窗口往前推，导致另一条几乎静默的流
/// 延迟到达的合法包被误判成"已滑出窗口"而丢弃——现象就是"能打洞成功，
/// 但过几分钟 TUN 转发开始规律性丢包直至整条隧道断线重连"。按五元组
/// 把窗口拆开后，一条流的突发不再能连累另一条流。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: u8,
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
}

/// 从已解密的 IP 包里提取流标识。没有端口概念的协议（比如 ICMP）
/// 端口取 0，相当于按（协议, 源, 目的）这一组粗粒度地共享一个窗口——
/// 这类流量本身速率很低，不会触发误杀。
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

/// 每个对端连接跟踪的流数量上限。
///
/// 只是防止对端伪造海量不同五元组的包把内存耗光；正常场景（哪怕是
/// BT 那种同时几百个对等连接）远用不到这个量级，触发上限只会按 FIFO
/// 淘汰最老的流，不影响正常流量。
const MAX_TRACKED_FLOWS: usize = 4096;

/// 按内层流拆分的重放检测表。只被单个 `receive_datagrams` 任务
/// 顺序访问，不需要加锁。
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
    let mut decoder = FecDecoder::new();
    let mut loss = LossTracker::new(Instant::now());
    let mut last_hello = Instant::now() - fec::HELLO_INTERVAL;
    let mut last_feedback = Instant::now();

    loop {
        // HELLO 周期性广播：1 字节/秒，让对端知道我们能收 FEC 格式。
        // 一直发（而不是协商成功就停）是为了让后加入/重连的对端也能学到。
        let now = Instant::now();
        if now.duration_since(last_hello) >= fec::HELLO_INTERVAL {
            last_hello = now;
            sender.send_raw(fec::hello_datagram());
        }
        // 入方向观测回传给发送端：A→B 的丢包只有 B 能看见，
        // 但决定 A→B 冗余率的是 A，所以必须由 B 主动反馈。
        if now.duration_since(last_feedback) >= fec::FEEDBACK_INTERVAL && loss.window_due(now) {
            last_feedback = now;
            let recovered_window = std::mem::take(&mut decoder.recovered_window);
            let report = loss.settle(now, recovered_window);
            sender.send_raw(report.encode());
            if report.raw_loss_bp > 0 {
                tracing::info!(
                    "[FEC] 入方向观测: 原始丢包 {:.2}% 残余 {:.2}% 本窗口恢复 {} 个",
                    report.raw_loss_bp as f64 / 100.0,
                    report.residual_loss_bp as f64 / 100.0,
                    report.recovered
                );
            }
        }

        let datagram = conn.read_datagram().await.map_err(|e| e.to_string())?;
        if let Some((stats, user)) = &sender.stats {
            let (stats, user, n) = (stats.clone(), user.clone(), datagram.len());
            tokio::spawn(async move { stats.record_receive(&user, n).await });
        }
        let now = Instant::now();

        // 同时接受两种格式：传统裸 sealed，以及 FEC 封装。
        // 判别靠首字节（见 fec 模块文档），旧版本永远落在传统分支。
        let mut sealed_batch: Vec<Vec<u8>> = Vec::new();
        if fec::is_fec(&datagram) {
            match decoder.accept(&datagram, now) {
                Incoming::Data(sealed) => sealed_batch.push(sealed),
                Incoming::Parity => {}
                Incoming::Hello => {
                    if sender.fec.mark_peer_ready() {
                        tracing::info!("[FEC] 对端支持前向纠错，本端切换到 FEC 格式发送");
                        sender.sync_redundancy();
                    }
                }
                Incoming::Control(report) => {
                    let redundancy = {
                        let mut c = sender
                            .fec
                            .controller
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        c.observe(report, now);
                        c.tick(now);
                        c.current()
                    };
                    let mut enc = sender.fec.encoder.lock().unwrap_or_else(|e| e.into_inner());
                    if enc.redundancy() != redundancy {
                        tracing::info!(
                            "[FEC] 对端报告丢包 {:.2}%，冗余调整为 k={} r={}（溢价 {}%）",
                            report.raw_loss_bp as f64 / 100.0,
                            redundancy.k,
                            redundancy.r,
                            redundancy.overhead_pct()
                        );
                        enc.set_redundancy(redundancy);
                    }
                }
                Incoming::Invalid => {
                    debug!("[FEC] 丢弃无法解析的 FEC 数据报 ({} 字节)", datagram.len());
                }
            }
            // 校验分片可能刚好补齐了某个残缺分组
            for rec in decoder.take_recovered(now) {
                sealed_batch.push(rec.sealed);
            }
        } else {
            sealed_batch.push(datagram.to_vec());
        }

        let recovered_now = decoder.recovered_total;
        if recovered_now > sender.fec.recovered.swap(recovered_now, Ordering::Relaxed) {
            let n = recovered_now;
            if n <= 20 || n % 100 == 0 {
                tracing::info!("[FEC] 累计已从丢包中恢复 {} 个数据报", n);
            }
        }

        for sealed in sealed_batch {
            // 解密失败不是致命错误：可能是认证不通过、或途中损坏。
            // 丢弃这一个包继续跑，绝不能因此中断整条隧道。
            let (counter, packet) = match sender.crypto.open(&sealed) {
                Ok(v) => v,
                Err(e) => {
                    debug!("[TUN] 丢弃无法解密的数据报: {}", e);
                    continue;
                }
            };
            loss.on_received(counter);
            let len = packet.len();
            if !(20..=MAX_PACKET).contains(&len) {
                debug!("[TUN] 丢弃长度异常的包: {}", len);
                continue;
            }
            let Some(header) = Ipv4Header::from_bytes(&packet) else {
                continue;
            };
            // 重放判定按内层流拆分（见 FlowKey 文档），必须在这里、拿到
            // 明文之后才能做——五元组在解密前是不可见的。
            //
            // 这一步同时天然完成了 FEC 的去重：一个包如果既直达、又被恢复出来，
            // 第二份会被当作重放丢掉，不需要额外的去重逻辑。
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

    /// 一个满 MTU 的包加上 overlay 加密与 FEC 开销后，必须仍能塞进 QUIC 数据报。
    ///
    /// QUIC 为避免 IP 分片会把数据报限制在保守的路径 MTU 内（典型 1200 左右）。
    /// 这个关系一旦破坏，**每一个满载包都会被拒发**——而且只在真实链路上
    /// 才暴露，本地环回测不出来，所以在这里用断言钉死。
    ///
    /// 最紧的一档是**校验报**：它总是满长度的（数据报可以按原始长度发，
    /// 但 parity 必须补齐到分组内最大分片）。
    #[test]
    fn full_mtu_packet_still_fits_in_a_quic_datagram() {
        // QUIC 在 IPv6 最小 MTU(1280) 下扣掉包头后的保守可用值
        const CONSERVATIVE_QUIC_DATAGRAM_LIMIT: usize = 1200;
        let sealed = TUN_MTU as usize + crate::crypto::OVERHEAD;

        let data_case = sealed + crate::fec::DATA_HEADER_LEN;
        assert!(
            data_case <= CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            "满载数据报 {} 超出 QUIC 保守上限 {}",
            data_case,
            CONSERVATIVE_QUIC_DATAGRAM_LIMIT
        );

        // 校验报 = FEC 校验头 + 分片(2 字节长度前缀 + sealed)
        let parity_case = crate::fec::PARITY_HEADER_LEN + 2 + sealed;
        assert!(
            parity_case <= CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            "满载校验报 {} 超出 QUIC 保守上限 {}（TUN_MTU={} 需下调）",
            parity_case,
            CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            TUN_MTU
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
