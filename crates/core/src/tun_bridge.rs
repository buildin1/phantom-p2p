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
use crate::repair::{self, LossDetector, LossyFlows, RepairPolicy, SendBuffer, SendQueue};
use crate::stats::StatsManager;
use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::Connection;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

const MAX_PACKET: usize = 65535;

/// 该对端的统计上报句柄（连接建立时才知道 user_id，故为 Option）
pub type PeerStats = Option<(Arc<StatsManager>, String)>;

/// TUN 设备 MTU。
///
/// 必须留出 QUIC DATAGRAM 的空间：QUIC 为避免 IP 分片会把数据报限制在
/// 保守的路径 MTU（典型 ~1200 字节）以内，还要再扣掉 overlay 加密的
/// [`crate::crypto::OVERHEAD`]（8 字节计数器 + 16 字节认证标签）。
///
/// 丢包修复层**不增加任何字节**——冗余副本与重传都是原报文的逐字节重发
/// （见 [`crate::repair`]），所以这里只需覆盖加密开销。
///
/// 取 1140 而非更大的值，是为了与 3.0.2 保持一致：混版本房间里两端 MTU
/// 不同会让内层 MSS 协商结果不可预期，多留的那 20 字节不值得冒这个险。
///
/// **不能直接取 1200**——那样每个满载包加密后都会超限被拒发，
/// 而这种故障只在真实链路上才暴露，本地环回测不出来。
/// `full_mtu_packet_still_fits_in_a_quic_datagram` 用断言钉死了这个关系。
pub const TUN_MTU: u16 = 1140;

/// 修复层巡检间隔：驱动冗余副本发送、NACK 轮询、心跳。
///
/// 必须远小于 [`repair::FIRST_COPY_DELAY`]，否则副本会被巡检粒度拖慢。
const REPAIR_TICK: Duration = Duration::from_millis(5);

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
/// 一个对端的丢包修复会话状态。
///
/// `peer_supports` 由**带内探测**得出（收到对端 HELLO 才置位），
/// 而不是靠信令协商——见 [`crate::repair`] 模块文档。这样做是失败安全的：
/// 任何一环出问题都只退回"什么都不做"，绝不会把对端看不懂的报文发出去把隧道搞断。
struct RepairSession {
    peer_supports: AtomicBool,
    policy: std::sync::Mutex<RepairPolicy>,
    /// 已发出报文的留存，供重传与冗余副本使用
    send_buffer: std::sync::Mutex<SendBuffer>,
    /// 哪些内层流最近丢过包——冗余只施加在这些流上，而不是全流放大
    lossy_flows: std::sync::Mutex<LossyFlows>,
    /// 排程待发的副本（故意延后发送以躲开突发丢包）
    queue: std::sync::Mutex<SendQueue>,
    /// 入方向丢包检测
    detector: std::sync::Mutex<LossDetector>,
    /// 本端已发出的最大计数器，随心跳告知对端以便它发现尾部丢包
    highest_sent: AtomicU64,
    /// 补包专用通道（中继）。
    ///
    /// P2P 已经证明它在丢包，从同一条烂路上补，大概率还是丢。所以重度丢包时
    /// 向信令求援借用中继，**只让补包走中继**，原包仍走 P2P：
    /// 既拿到了中继的可靠性，又不用付全流量走中继的带宽代价。
    repair_conn: std::sync::Mutex<Option<Connection>>,
    /// 本地发送失败计数。用于区分「网络丢包」与「本地发送队列丢包」——
    /// 后者是拥塞窗口耗尽导致的，包根本没上过网络，补包完全帮不上忙。
    send_failures: AtomicU64,
    copies_sent: AtomicU64,
    retransmits: AtomicU64,
}

impl RepairSession {
    fn new(now: Instant) -> Self {
        Self {
            peer_supports: AtomicBool::new(false),
            // 从该网络此前学到的安全上限起步，而不是每次重新试探到被掐
            policy: std::sync::Mutex::new(RepairPolicy::with_ceiling(repair::current_ceiling())),
            send_buffer: std::sync::Mutex::new(SendBuffer::new()),
            lossy_flows: std::sync::Mutex::new(LossyFlows::new()),
            queue: std::sync::Mutex::new(SendQueue::new()),
            detector: std::sync::Mutex::new(LossDetector::new(now)),
            highest_sent: AtomicU64::new(0),
            repair_conn: std::sync::Mutex::new(None),
            send_failures: AtomicU64::new(0),
            copies_sent: AtomicU64::new(0),
            retransmits: AtomicU64::new(0),
        }
    }

    /// 挂上/摘下补包专用通道
    fn set_repair_conn(&self, conn: Option<Connection>) {
        let mut c = self.repair_conn.lock().unwrap_or_else(|e| e.into_inner());
        *c = conn;
    }

    fn repair_conn(&self) -> Option<Connection> {
        self.repair_conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn peer_ready(&self) -> bool {
        self.peer_supports.load(Ordering::Relaxed)
    }

    /// 首次得知对端支持修复时返回 true（用于只打一次日志）
    fn mark_peer_ready(&self) -> bool {
        !self.peer_supports.swap(true, Ordering::Relaxed)
    }
}

/// 把内层五元组压成一个哈希。
///
/// 发送端要按流决定"这条流要不要加冗余"，但没必要保留完整五元组——
/// 只需要一个稳定的标识把同一条流认出来。
fn flow_hash(header: &Ipv4Header, packet: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    flow_key(header, packet).hash(&mut h);
    h.finish()
}

#[derive(Clone)]
struct PeerForwarder {
    conn: Connection,
    /// overlay 端到端加密。中继模式下 QUIC 是逐跳的，中继能看到明文，
    /// 机密性必须由这一层保证。
    crypto: Arc<SessionCrypto>,
    repair: Arc<RepairSession>,
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
                // 与网络丢包是两回事，必须分开计数，否则会误判病因：
                // 这类丢包补包完全帮不上忙，要靠调拥塞控制解决。
                let n = self.repair.send_failures.fetch_add(1, Ordering::Relaxed) + 1;
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
        // 对端不支持修复（旧版本）：原样发走，零额外开销，保证互通
        if !self.repair.peer_ready() {
            return self.send_raw(sealed);
        }

        let now = Instant::now();
        let counter = crate::crypto::counter_of(&sealed).unwrap_or(0);
        let flow = Ipv4Header::from_bytes(packet)
            .map(|h| flow_hash(h, packet))
            .unwrap_or(0);

        // 档位决定要不要给这个包排冗余副本
        let level = {
            let p = self.repair.policy.lock().unwrap_or_else(|e| e.into_inner());
            p.level()
        };
        let protect = level.copies > 0
            && (level.all_flows || {
                let f = self
                    .repair
                    .lossy_flows
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                f.is_lossy(flow, now)
            });

        // 留存供重传/副本使用。即使这次不排副本也要存——
        // 对端随时可能 NACK 它。
        let stored: Arc<[u8]> = Arc::from(&sealed[..]);
        {
            let mut b = self
                .repair
                .send_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            b.push(counter, flow, stored.clone(), now);
        }
        self.repair
            .highest_sent
            .fetch_max(counter, Ordering::Relaxed);

        if protect {
            // 副本**故意延后**：紧跟原包发出的副本，一次持续两个包的突发
            // 就能把正副两份一起带走，冗余等于白加。
            let mut q = self.repair.queue.lock().unwrap_or_else(|e| e.into_inner());
            for i in 0..level.copies {
                let delay = repair::FIRST_COPY_DELAY + repair::COPY_SPACING * i as u32;
                q.schedule(now + delay, stored.clone());
            }
        }

        // 原包立即发出，绝不为了冗余而缓冲——修复层对正常路径零延迟惩罚
        self.send_raw(sealed)
    }

    /// 定时巡检：发出到期的冗余副本
    fn flush_due(&self, now: Instant) -> usize {
        let due = {
            let mut q = self.repair.queue.lock().unwrap_or_else(|e| e.into_inner());
            q.take_due(now)
        };
        let n = due.len();
        for payload in due {
            self.repair.copies_sent.fetch_add(1, Ordering::Relaxed);
            self.send_raw(payload.to_vec());
        }
        n
    }

    /// 应对端请求重传若干报文。
    ///
    /// 顺带把这些报文所属的流标记为"最近丢过包"——接收端无法告诉我们
    /// 哪条流在丢（它连那个包都没收到，看不到五元组），但发送端这里有
    /// 计数器到流的映射，于是能反推出来，从而只对这些流加冗余。
    fn retransmit(&self, counters: &[u64], now: Instant) -> usize {
        // 两把锁分开取，不嵌套——嵌套的取锁顺序一旦和别处相反就是死锁
        let mut payloads = Vec::new();
        let mut flows = Vec::new();
        {
            let b = self
                .repair
                .send_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for c in counters {
                if let Some((flow, payload)) = b.get(*c) {
                    flows.push(flow);
                    payloads.push(payload);
                }
            }
        }
        {
            let mut f = self
                .repair
                .lossy_flows
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for flow in flows {
                f.mark(flow, now);
            }
        }
        // 有中继可用就走中继补：P2P 已经证明它在丢包，
        // 从同一条烂路上补大概率还是丢。
        let via_relay = self.repair.repair_conn();
        let n = payloads.len();
        for p in payloads {
            self.repair.retransmits.fetch_add(1, Ordering::Relaxed);
            match &via_relay {
                Some(relay) => {
                    if relay.send_datagram(p.to_vec().into()).is_err() {
                        // 中继也发不出去就退回主路，尽力而为
                        self.send_raw(p.to_vec());
                    }
                }
                None => {
                    self.send_raw(p.to_vec());
                }
            }
        }
        n
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
    /// 必须显式持有：接收任务与修复巡检都循环在各自的 `Connection` 上，
    /// 只丢掉 `Arc<TunBridge>` 是停不掉它们的——那些任务各自克隆了连接句柄。
    /// 不在这里逐个 `close()` 的话，关了房间旧会话仍然能收发。
    conns: Mutex<Vec<Connection>>,
    /// 按内层流拆分的重放窗口，**全会话共享**。
    ///
    /// 不能做成每个接收任务一份：切换传输（P2P ↔ 中继）时两条路会短暂并存，
    /// 各自一份窗口就意味着同一个报文经两条路到达时都能通过，
    /// 重复写进 TUN。共享之后去重才是全局有效的。
    replay: Arc<std::sync::Mutex<FlowReplayTable>>,
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
            replay: Arc::new(std::sync::Mutex::new(FlowReplayTable::new())),
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
        self.attach_peer_inner(conn, crypto, peer_hint, stats, false)
            .await
    }

    /// 接入一条新连接并**把它设为默认出口**，用于 P2P → 中继的无缝切换。
    ///
    /// 与 [`attach_peer`](Self::attach_peer) 的区别只在最后一步：那个版本只在
    /// 默认出口还空着时才填，切换时必须强制改指向，否则出方向的包会继续
    /// 往那条已经废掉的旧路上送。
    ///
    /// 采用**先建后拆**：这里只负责建好并改指向，旧连接由调用方在确认新路
    /// 通了之后再关，中间没有空窗期，游戏的 TCP 连接不会断。
    pub async fn attach_and_promote(
        &self,
        conn: Connection,
        crypto: Arc<SessionCrypto>,
        stats: PeerStats,
    ) -> Result<(), TunError> {
        self.attach_peer_inner(conn, crypto, None, stats, true)
            .await
    }

    async fn attach_peer_inner(
        &self,
        conn: Connection,
        crypto: Arc<SessionCrypto>,
        peer_hint: Option<Ipv4Addr>,
        stats: PeerStats,
        promote: bool,
    ) -> Result<(), TunError> {
        // 切换到一条数据报上限更小的路，会让满载包突然开始被拒发，
        // 而 TUN 的 MTU 在设备创建时就定死了、运行中改不了。宁可不切。
        let required = TUN_MTU as usize + crate::crypto::OVERHEAD;
        if let Some(limit) = conn.max_datagram_size() {
            if limit < required {
                return Err(TunError::CreateFailed(format!(
                    "对端数据报上限 {} 小于满载包所需 {}，接入会导致满载包被拒发",
                    limit, required
                )));
            }
        }

        let forwarder = PeerForwarder {
            conn: conn.clone(),
            crypto,
            repair: Arc::new(RepairSession::new(Instant::now())),
            stats,
        };
        tracing::info!(
            "[TUN] 数据报通道就绪 (local={}, peer_hint={:?}, host={}, promote={}, max_datagram={:?})",
            self.my_vip,
            peer_hint,
            self.is_host,
            promote,
            conn.max_datagram_size()
        );
        self.conns.lock().await.push(conn.clone());
        if let Some(ip) = peer_hint {
            self.peers.lock().await.insert(ip, forwarder.clone());
        }
        {
            let mut default = self.default_peer.lock().await;
            if promote || (!self.is_host && default.is_none()) {
                *default = Some(forwarder.clone());
            }
        }

        // 修复层的定时工作必须独立于收包循环：稀疏流量下包与包之间隔着几十毫秒，
        // 挂在收包上驱动的话，副本发送、NACK 重试、心跳全都会被拖到下一个包才动。
        // 随连接结束自动退出，不会留下孤儿任务。
        spawn_repair_ticker(forwarder.clone(), conn.clone());

        let tun = self.tun.clone();
        let peers = self.peers.clone();
        let replay = self.replay.clone();
        let sender = forwarder;
        let is_host = self.is_host;
        let host_vip = self.host_vip;
        let guest_network = self.guest_network;
        tokio::spawn(async move {
            if let Err(e) = receive_datagrams(
                conn,
                tun,
                peers,
                replay,
                sender,
                is_host,
                host_vip,
                guest_network,
            )
            .await
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
        // 必须显式关掉每条连接。接收任务和修复巡检各自克隆了连接句柄，
        // 光丢引用是停不掉它们的——不关的话关了房间旧会话仍然能收发。
        // 关掉之后 `read_datagram()` 立刻返回错误，两个任务自然退出。
        for conn in self.conns.lock().await.drain(..) {
            conn.close(0u32.into(), b"tunnel closed");
        }
        self.peers.lock().await.clear();
        *self.default_peer.lock().await = None;
        self.tun.close().await;
    }

    /// 关闭除当前默认出口之外的所有连接。
    ///
    /// 无缝切换的收尾：新路已经确认可用、默认出口也已改指向之后，
    /// 才把旧路撤掉，中间不留空窗期。
    pub async fn retire_inactive_peers(&self) {
        let keep = self
            .default_peer
            .lock()
            .await
            .as_ref()
            .map(|f| f.conn.stable_id());
        let mut conns = self.conns.lock().await;
        let mut retained = Vec::new();
        for conn in conns.drain(..) {
            if Some(conn.stable_id()) == keep {
                retained.push(conn);
            } else {
                tracing::info!("[TUN] 撤下旧传输通道 {}", conn.remote_address());
                conn.close(0u32.into(), b"superseded");
            }
        }
        *conns = retained;
    }

    /// 给所有对端挂上补包专用通道（中继），或传 `None` 摘下。
    ///
    /// 只影响**补包**：原包仍走各自的主路。
    pub async fn set_repair_channel(&self, conn: Option<Connection>) {
        if let Some(f) = self.default_peer.lock().await.as_ref() {
            f.repair.set_repair_conn(conn.clone());
        }
        for f in self.peers.lock().await.values() {
            f.repair.set_repair_conn(conn.clone());
        }
        match &conn {
            Some(c) => tracing::info!("[修复] 补包改走中继 {}", c.remote_address()),
            None => tracing::info!("[修复] 补包改回 P2P 直连"),
        }
    }

    /// 当前观测到的最差入方向丢包率（万分之一），供上层决定要不要求援
    pub async fn worst_observed_loss_bp(&self) -> u16 {
        let mut worst = 0u16;
        let mut consider = |f: &PeerForwarder| {
            let p = f.repair.policy.lock().unwrap_or_else(|e| e.into_inner());
            worst = worst.max(p.smoothed_loss_bp());
        };
        if let Some(f) = self.default_peer.lock().await.as_ref() {
            consider(f);
        }
        for f in self.peers.lock().await.values() {
            consider(f);
        }
        worst
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

/// 修复层的定时驱动任务。
///
/// 独立于收包循环是必须的：稀疏流量下包与包之间隔着几十毫秒，
/// 如果把这些定时工作挂在收包上驱动，冗余副本、NACK 重试、心跳
/// 全都要等到下一个包到达才动——而"下一个包迟迟不来"恰恰就是丢包的场景。
fn spawn_repair_ticker(sender: PeerForwarder, conn: Connection) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REPAIR_TICK);
        let mut last_hello = Instant::now() - repair::HELLO_INTERVAL;
        let mut last_heartbeat = Instant::now();
        let mut observed_loss_bp: u16 = 0;
        let mut last_level = usize::MAX;

        loop {
            tick.tick().await;
            if let Some(reason) = conn.close_reason() {
                note_disconnect(&sender, &reason);
                break;
            }
            let now = Instant::now();

            // 能力宣告：1 字节/秒。一直发（而不是协商成功就停）
            // 是为了让重连或后加入的对端也能学到。
            if now.duration_since(last_hello) >= repair::HELLO_INTERVAL {
                last_hello = now;
                sender.send_raw(repair::hello_datagram());
            }

            // 到期的冗余副本
            sender.flush_due(now);

            if sender.repair.peer_ready() {
                // NACK：请求对端补发已经确认丢失的报文
                let nack = {
                    let mut d = sender
                        .repair
                        .detector
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    d.poll_nack(now)
                };
                if let Some(missing) = nack {
                    if let Some(datagram) = repair::encode_nack(&missing) {
                        sender.send_raw(datagram);
                    }
                }

                // 心跳：捎带本端已发到第几号（让对端发现尾部丢包），
                // 以及本端观测到的入方向丢包率（对端据此决定要发几份冗余）。
                if now.duration_since(last_heartbeat) >= repair::HEARTBEAT_INTERVAL {
                    last_heartbeat = now;
                    let highest = sender.repair.highest_sent.load(Ordering::Relaxed);
                    sender.send_raw(repair::heartbeat_datagram(highest, observed_loss_bp));
                }
            }

            // 结算入方向丢包窗口
            {
                let mut d = sender
                    .repair
                    .detector
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if d.window_due(now) {
                    observed_loss_bp = d.settle(now);
                    if observed_loss_bp > 0 {
                        tracing::info!(
                            "[修复] 入方向丢包 {:.2}%，累计已补回 {} 个包，待补 {} 个",
                            observed_loss_bp as f64 / 100.0,
                            d.repaired_total,
                            d.pending_holes()
                        );
                    }
                }
            }

            // 档位维护与过期回收
            {
                let mut p = sender
                    .repair
                    .policy
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                p.tick(now);
                let level = p.level_index();
                if level != last_level {
                    last_level = level;
                    let l = p.level();
                    tracing::info!(
                        "[修复] 冗余档位 → {}（对端丢包 {:.2}%，每包补发 {} 份，{}）",
                        level,
                        p.smoothed_loss_bp() as f64 / 100.0,
                        l.copies,
                        if l.all_flows {
                            "全部流"
                        } else {
                            "仅丢过包的流"
                        }
                    );
                }
            }
            {
                let mut b = sender
                    .repair
                    .send_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                b.expire(now);
            }
            {
                let mut f = sender
                    .repair
                    .lossy_flows
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                f.expire(now);
            }
        }
    });
}

/// 接收对端数据报，解密后写入 TUN。
///
/// 与旧的流式实现相比，这里**丢包不影响后续包**——数据报之间彼此独立，
/// 不存在队头阻塞，也不会为早已过期的实时流量做重传。
/// 单个包解密失败只丢它自己，循环继续。
#[allow(clippy::too_many_arguments)]
async fn receive_datagrams(
    conn: Connection,
    tun: Arc<TunDevice>,
    peers: PeerSenders,
    replay: Arc<std::sync::Mutex<FlowReplayTable>>,
    sender: PeerForwarder,
    is_host: bool,
    host_vip: Ipv4Addr,
    guest_network: Ipv4Addr,
) -> Result<(), String> {
    loop {
        let datagram = conn.read_datagram().await.map_err(|e| e.to_string())?;
        if let Some((stats, user)) = &sender.stats {
            let (stats, user, n) = (stats.clone(), user.clone(), datagram.len());
            tokio::spawn(async move { stats.record_receive(&user, n).await });
        }
        let now = Instant::now();

        // 控制报文与数据报靠首字节区分（见 repair 模块文档）：
        // 传统数据报首字节是计数器最高位，恒为 0；控制报文 bit7 恒为 1。
        // 旧版本永远落在数据分支，不受影响。
        if repair::is_control(&datagram) {
            handle_control(&datagram, &sender, now);
            continue;
        }

        {
            // 解密失败不是致命错误：可能是认证不通过、或途中损坏。
            // 丢弃这一个包继续跑，绝不能因此中断整条隧道。
            let (counter, packet) = match sender.crypto.open(&datagram) {
                Ok(v) => v,
                Err(e) => {
                    debug!("[TUN] 丢弃无法解密的数据报: {}", e);
                    continue;
                }
            };
            {
                let mut d = sender
                    .repair
                    .detector
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                d.on_received(counter, now);
            }
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
            // 这一步同时天然完成了修复层的去重：冗余副本与重传都是原报文的
            // 逐字节重发、计数器相同，第二份会被当作重放丢掉。
            // 于是**本地 TUN 永远只收到每个 IP 包恰好一份**，多倍包只存在于
            // P2P 双端之间——这是不能破坏的性质。
            let key = flow_key(header, &packet);
            let accepted = {
                let mut flows = replay.lock().unwrap_or_else(|e| e.into_inner());
                flows.accept(key, counter)
            };
            if !accepted {
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

/// 连接结束时判断是否疑似触发了运营商风控。
///
/// **只把异常断开算数**：对端正常关房间同样会让连接结束，若不加区分，
/// 每次正常退出都会被当成风控，把冗余上限一路压到零保护。
/// `ApplicationClosed`/`LocallyClosed` 是双方谈好的关闭，不算；
/// 超时与被重置才是"被人掐断"的样子。
fn note_disconnect(sender: &PeerForwarder, reason: &quinn::ConnectionError) {
    use quinn::ConnectionError::*;
    let abnormal = matches!(reason, TimedOut | Reset);
    if !abnormal {
        return;
    }
    let lowered = {
        let mut p = sender
            .repair
            .policy
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        p.on_abnormal_disconnect(Instant::now())
    };
    if let Some(ceiling) = lowered {
        warn!(
            "[修复] 隧道在提高冗余后不久被异常掐断（{}），疑似触发运营商风控；\
             已把冗余上限降到 {} 并记住该网络",
            reason, ceiling
        );
        repair::save_ceiling(&repair::current_network(), ceiling);
    }
}

/// 处理修复层的控制报文。
///
/// 控制报文**永远不会**被写进 TUN——它们不是用户数据，只是双端之间的协调信息。
fn handle_control(datagram: &[u8], sender: &PeerForwarder, now: Instant) {
    // HELLO：对端宣告它支持丢包修复
    if datagram.len() == 1 && datagram[0] == repair::CTRL_MARKER | repair::CTRL_HELLO {
        if sender.repair.mark_peer_ready() {
            tracing::info!("[修复] 对端支持丢包修复，本端启用补包");
        }
        return;
    }

    // NACK：对端请求补发若干报文
    if let Some(missing) = repair::decode_nack(datagram) {
        let n = sender.retransmit(&missing, now);
        if n > 0 {
            debug!("[修复] 应对端请求补发 {}/{} 个报文", n, missing.len());
        }
        return;
    }

    // 心跳：对端已发到第几号（用于发现尾部丢包）+ 它观测到的入方向丢包率
    if let Some((peer_highest, peer_loss_bp)) = repair::parse_heartbeat(datagram) {
        {
            let mut d = sender
                .repair
                .detector
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            d.observe_peer_highest(peer_highest, now);
        }
        // 对端报告的是**它那一侧**的入方向丢包，也就是本端发出去的包丢了多少——
        // 所以这个数字该用来调整**本端**的冗余强度。
        let mut p = sender
            .repair
            .policy
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        p.observe(peer_loss_bp, now);
        return;
    }

    debug!("[修复] 丢弃无法解析的控制报文 ({} 字节)", datagram.len());
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
        let sealed = TUN_MTU as usize + crate::crypto::OVERHEAD;
        assert!(
            sealed <= CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            "满载数据报 {} 超出 QUIC 保守上限 {}（TUN_MTU={} 需下调）",
            sealed,
            CONSERVATIVE_QUIC_DATAGRAM_LIMIT,
            TUN_MTU
        );
    }

    /// 修复层不得给数据报增加任何字节：冗余副本与重传都是原报文的逐字节重发。
    ///
    /// 一旦有人给数据报加了头部，满载包就可能超限被拒发，而这种故障
    /// 只在真实链路上才暴露。这条断言把"修复层零字节开销"这个前提钉死。
    #[test]
    fn repair_layer_adds_no_bytes_to_data_path() {
        let sealed = vec![0u8; TUN_MTU as usize + crate::crypto::OVERHEAD];
        assert!(
            !crate::repair::is_control(&sealed),
            "数据报绝不能被当成控制报文"
        );
        // 控制报文是独立的报文，不寄生在数据报里
        assert!(crate::repair::is_control(&crate::repair::hello_datagram()));
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
