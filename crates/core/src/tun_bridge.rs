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

use crate::crypto::{ReplayVerdict, ReplayWindow, SessionCrypto};
use crate::stats::StatsManager;
use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::Connection;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
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

/// 冗余包相对原包的发送延迟。
///
/// 定时器驱动是唯一能跑赢内层 TCP 自愈的手段——见《抗丢包方案设计》第四节：
/// 反应式重传和"等下一个正常包顺路捎带"都要等到下一个包才能触发，游戏
/// 20~30 包/秒的间隔（33~50ms）本身就追不上内层 TCP 约 55ms 的 RACK-TLP
/// 自愈窗口。15ms 后补发一次，最坏情况恢复时间约等于延迟+单程时延，
/// 能跑赢那 55ms。
const REDUNDANCY_DELAY: Duration = Duration::from_millis(15);

/// 补发多份时，相邻两份之间的错峰间隔。
///
/// 不能紧挨着发——一次突发丢包会把挨在一起的两份一起带走，冗余等于白加。
/// 错开发送才是为突发丢包地区留的余量。
const REDUNDANCY_STAGGER: Duration = Duration::from_millis(10);

/// 不管这次要补几份，从原包发出到最后一份补发完，总耗时不能超过这个上限。
///
/// 份数按丢包率升到 [`MAX_EXTRA_COPIES`] 档之后，如果还按固定
/// [`REDUNDANCY_STAGGER`] 错峰，最后一份会拖到 85ms 才发出去——比内层 TCP
/// 约 55ms 的自愈窗口还慢，纯属陪跑，起不到"抢在卡顿被感知到之前补上"
/// 的作用。份数一多就按这个上限压缩间隔，见 [`redundancy_delay_for`]。
const REDUNDANCY_WINDOW_CAP: Duration = Duration::from_millis(60);

/// 补 `extra_copies` 份时，第 `i`（0 起）份相对原包该等多久再发。
///
/// 份数不多时维持固定的 [`REDUNDANCY_STAGGER`] 间隔，跟以前行为一致；
/// 份数多到会把最后一份推到 [`REDUNDANCY_WINDOW_CAP`] 之后时，压缩间隔让
/// 全部补发挤进这个窗口——宁可挤得密一点多担一点"一次突发全带走"的风险，
/// 也不要让补发本身晚到失去意义。
fn redundancy_delay_for(i: u8, extra_copies: u8) -> Duration {
    if extra_copies <= 1 {
        return REDUNDANCY_DELAY;
    }
    let budget = REDUNDANCY_WINDOW_CAP.saturating_sub(REDUNDANCY_DELAY);
    let interval = std::cmp::min(REDUNDANCY_STAGGER, budget / (extra_copies as u32 - 1));
    REDUNDANCY_DELAY + interval * i as u32
}

/// 一条流检测到丢包后，主动冗余保持开启的时长。
///
/// 期间内这条流安静下来（没有新的 NACK 命中）就让它自然过期关闭，
/// 不需要显式的"关闭"事件——干净的流完全不产生冗余流量，这是刻意的：
/// 冗余必须跟着实测丢包走、按流精确定向，不能全局常开去撞运营商风控。
const REDUNDANCY_HOLD: Duration = Duration::from_secs(4);

/// RTT 超过"这条连接见过的最小 RTT"多少倍，判定为链路正在拥塞。
///
/// 基线用这条连接自己的历史最小 RTT，而不是写死的常量——不同链路的物理
/// 延迟差异很大，只有拿它自己的最优值当基准才公平（BBR 判断拥塞用的也是
/// 同一个思路）。RTT 持续、明显地偏离这个基线，是排队/拥塞最直接的信号。
///
/// 实机联机测出过这个坑：一旦测到的丢包率把冗余档位推到顶（`MAX_EXTRA_COPIES`
/// 8 份），如果这次丢包本身就是链路拥塞造成的，补 9 倍流量上去只会让拥塞
/// 更重——拥塞导致丢包更多，更多丢包又把档位摁在顶不下来，形成恶性循环，
/// 实测 12 秒内同一条流的重复/过旧拒收事件飙到 4000+ 次，最后直接把游戏
/// 连接拖到重置。WebRTC/RFC 8854 对这个问题的标准做法是：补发流量必须
/// 服从拥塞控制给出的带宽上限，链路已经拥塞时应该降补发量而不是加——
/// 这里就是那个"降"的开关。
const CONGESTION_RTT_MULTIPLIER: u64 = 3;

/// 判定为拥塞时，无论测出的丢包率多高，冗余档位最多压到这个值。
///
/// **压到 0，不是 1。** 曾经是 1，理由写的是"已经被 NACK 证实丢包的流仍然值得担
/// 一份最基本的冗余"——但判定为拥塞时，那一份副本恰恰**就是**丢包的来源，
/// 再留一份等于继续给正在溢出的队列加料。而且拥塞丢包是突发的，错峰几十毫秒的
/// 副本会和原包一起被同一次队列溢出吞掉，物理上救不回来。
///
/// 这条流并没有失去保护：ARQ（NACK 重传）照常覆盖它，而且 ARQ 在拥塞时是**自限**
/// 的（要等对端发现空洞才触发，链路越堵触发越慢），冗余不是（不管链路什么状态都
/// 按固定倍率往外推）。拥塞时正确的机制本来就是 ARQ。
const CONGESTED_TIER_CAP: u8 = 0;

/// 纯逻辑判断，不摸真实时钟——方便单测，不用真建一条 QUIC 连接。
fn is_congested(min_rtt_ms: u64, current_rtt_ms: u64) -> bool {
    min_rtt_ms != u64::MAX && current_rtt_ms > min_rtt_ms.saturating_mul(CONGESTION_RTT_MULTIPLIER)
}

/// 补发流量（冗余份 + NACK 重传）的硬性速率上限——每条连接每秒最多发这么
/// 多份补发包，不管上面 tier 算出来该补多少。
///
/// 这是最后一道硬闸门，不依赖"拥塞判断得准不准"：就算上面的 RTT 检测这次
/// 没抓住（比如拥塞发生在对端、本端自己测的 RTT 没体现出来），补发流量
/// 物理上也不可能超过这个数，从根上堵死"冗余把链路自己压垮"这种失控放大。
const MAX_REPAIR_PACKETS_PER_SEC: u32 = 300;

/// 纯逻辑：给定补发预算窗口的当前状态和这一刻的时间，算出这次要不要放行、
/// 放行/拒绝之后窗口状态该更新成什么样。不摸真实时钟或锁，方便单测。
fn reserve_repair_budget(window_start: Instant, used: u32, now: Instant) -> (bool, Instant, u32) {
    let (window_start, used) = if now.duration_since(window_start) >= Duration::from_secs(1) {
        (now, 0)
    } else {
        (window_start, used)
    };
    if used < MAX_REPAIR_PACKETS_PER_SEC {
        (true, window_start, used + 1)
    } else {
        (false, window_start, used)
    }
}

/// NACK 请求重传的最长等待时间，**按这条连接实测的 RTT 动态算**，不能写死。
///
/// 曾经写死成 150ms，在低延迟链路上没问题，但拿到一条真实高丢包链路
/// （RTT 200~330ms）实测后发现：补包机制完全没触发过一次。算一下账就知道
/// 为什么——NACK 走完一圈至少要「重排容忍期 + NACK 单程 + 重发单程」，
/// 单程网络延迟就接近半个 RTT，两段单程加起来接近一整个 RTT。写死
/// 150ms 的话，NACK 还没到发送端，发送缓冲里的条目就已经被判定"过期"
/// 清掉了——RTT 越高、越需要补包的链路，反而越注定失效。
///
/// 下限 [`ARQ_DEADLINE_FLOOR`] 保住原来低延迟链路上就验证过的数值；
/// 上限 [`ARQ_DEADLINE_CEILING`] 防止极端高 RTT 链路把这个值撑到不合理。
const ARQ_DEADLINE_FLOOR: Duration = Duration::from_millis(150);
const ARQ_DEADLINE_CEILING: Duration = Duration::from_secs(2);

/// 用当前连接的 RTT 算出这次该用的 ARQ 截止时间。
///
/// 取 `2×RTT + 50ms`：NACK 一圈大约要 1 个 RTT，乘 2 留出往返抖动的余量，
/// 再加一点固定余量兜底极低 RTT 场景下的调度/处理开销。
fn arq_deadline_for(rtt: Duration) -> Duration {
    (rtt * 2 + Duration::from_millis(50)).clamp(ARQ_DEADLINE_FLOOR, ARQ_DEADLINE_CEILING)
}

/// 发现空洞后，先给这么久的重排容忍期——大概率只是乱序到达，不是真丢。
/// 数据报本就无序，超过这个时间还没等到才真正当成丢包去 NACK。
const REORDER_GRACE: Duration = Duration::from_millis(20);

/// NACK 最多多久发一次，把这段时间内新发现的空洞打包一起发。
///
/// 不限速的话，一次突发丢包会让 NACK 自己的包速率瞬间顶高，正撞运营商
/// 对 UDP 流量的风控——补救丢包的机制反倒成了触发风控的原因，本末倒置。
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(10);

/// 一条 NACK 最多带多少个区间，避免链路极端时把 NACK 本身的报文撑爆。
const NACK_MAX_RANGES: usize = 32;

/// 发送缓冲最多保留这么多个最近发送的包，用于 NACK 命中时原样重发。
/// 超过 ARQ 截止时间（[`arq_deadline_for`]）的条目即使还在缓冲里也不会再被用来重传。
const SEND_BUFFER_CAP: usize = 512;

/// 心跳间隔：定期把"目前发到的最大计数器"告诉对端。
///
/// 主动冗余和 NACK 都只能补"两个已知序号之间"的空洞——如果对端发的最后
/// 几个包全丢了，本端根本不知道那些序号存在过（没有后续包暴露这个空洞）。
/// 心跳把发送端自己知道的最大计数器带过去，接收端一比对就能发现尾部缺口，
/// 照样能触发 NACK 补上。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// 控制报文标签，取值故意避开合法 IPv4 首字节。
///
/// IPv4 首字节高 4 位固定是版本号 4（即 0x40~0x4F），所以任何高 4 位不是 4
/// 的字节都不可能是一个真实 IP 包的开头。解密后不用再包一层信封、
/// 不用额外占用报文空间，直接看首字节就能把控制报文和数据报文分开。
const CTRL_NACK: u8 = 0xF1;
const CTRL_HEARTBEAT: u8 = 0xF2;

fn looks_like_ipv4(first_byte: u8) -> bool {
    first_byte >> 4 == 4
}

/// 从密文头部读出计数器，仅用于日志把原包和补包对应起来——不解密。
/// 报文格式见 `crypto.rs`：`[8字节大端计数器][密文+16字节tag]`。
fn counter_of(sealed: &[u8]) -> u64 {
    sealed
        .get(..8)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

/// 补发份数的硬上限（不含原包）。
///
/// **曾经是 8，是错的。** 那个值的依据是一句注释——"这版实验性构建不考虑带宽放大
/// （见《抗丢包方案设计》第一节的范围声明）"——而第一节**没有这条声明**：它的非目标
/// 只有"中继路径补包"和"风控自校准持久化"两条，并且明确要求风控用"一个写死的保守
/// 上限"。该表述实际只存在于第 4.5 节，而 4.5 节又反向引用第一节，整条引用链是空的。
/// 第 4.4 节、第五节、《踩坑记录》第十一条方向完全相反，都在警告速率放大是运营商
/// 风控的头号触发点。
///
/// 用文档自己第 4.5 节的公式（残余丢包 ≈ `p^(k+1)`）反推真正需要的份数：
/// p=1% 时补 1 份残余就只剩 0.01%，p=5% 时补 2 份剩 0.0125%。**补 2 份足够覆盖
/// 任何还值得用冗余去救的链路**；需要更多份意味着 p 高到几乎必然是拥塞，
/// 而拥塞丢包是突发的（队列溢出连丢一串），错峰几十毫秒的副本会和原包一起被吞——
/// 冗余对拥塞丢包在物理上就是无效的，加份数只会让拥塞更重。
const MAX_EXTRA_COPIES: u8 = 2;

/// 按最近一次测得的丢包率，决定冗余档位（额外补发份数，不含原包）。
///
/// | 丢包率 | 额外份数 | 总份数 |
/// |---|---|---|
/// | <0.2% | 0 | 1 |
/// | 0.2~5% | 1 | 2 |
/// | 5%+ | 2（[`MAX_EXTRA_COPIES`]） | 3 |
///
/// **这张表曾经有个悬崖：只要测到任何丢包（哪怕 0.01%）就直接跳到 2 份额外拷贝，
/// 也就是流量立刻三倍**，中间没有任何过渡，一路陡到 20% 丢包时 9 倍。
/// 而 0.1%~0.5% 的丢包在公网上完全正常，内层 TCP 自己就能消化。
/// 实测后果是一个正反馈环：大流量占满链路 → 出现正常的微量丢包 → 档位跳到 3 倍
/// → 副本把原包挤出 QUIC 数据报发送缓冲（quinn 满时丢最旧的）→ 测到的丢包率
/// 不降反升 → 档位继续爬 → RTT 从 35ms 塌到 5 秒 → 连接超时。
/// macOS↔Windows 和 Windows↔Windows 都复现，纯单倍包时代从未出现过。
///
/// 现在的曲线按残余丢包 `p^(k+1)` 反推，只在真正需要时才加码：
/// 0.2% 以下不补（这个量级内层协议自愈更划算），5% 以下补 1 份（残余 ≤0.25%），
/// 再往上补 2 份封顶。
///
/// `bp == 0` 必须映射到 0，不能给个"最低也算一档"的下限——这个值同时也是
/// 连接级的**预测基线**（见 [`effective_extra_copies`]），链路真的干净时
/// 基线要能跟着降到 0，不然新流量会一直白白多发，冗余没法在链路恢复之后
/// 自己关掉。
fn tier_for_bp(bp: u16) -> u8 {
    if bp < 20 {
        // <0.2%：内层 TCP 的 RACK-TLP 自愈成本远低于给全链路加一份流量。
        0
    } else if bp <= 500 {
        1
    } else {
        MAX_EXTRA_COPIES
    }
}

/// 一个包实际该补几份：连接级预测基线 与 这条流自己被 NACK 命中过的
/// 实测档位，取较大值。
///
/// 基线覆盖的是"这条流还没机会自证丢没丢"的情况——连接最近测出来在丢包，
/// 新流量/低频流量（比如 ICMP ping，一次只发一个、隔很久才发下一个）
/// 很可能要等很久才能靠自己触发一次 NACK，等不起就先按连接的整体水平垫底。
/// 一旦这条流真的被 NACK 命中过（探测针给出了实测结果），说明预测该往上修
/// 正了，取较大值；探测针只会把保护"往上修"，不会把连接当前还在丢包时的
/// 基线"往下压"——旧的探测结果不该盖过更新鲜的连接级信号。
fn effective_extra_copies(baseline_tier: u8, flow_specific: Option<u8>) -> u8 {
    baseline_tier.max(flow_specific.unwrap_or(0))
}

/// 编码一条 NACK：`[0xF1][u16 区间数][ (u64 起始计数器, u16 区间长度) ... ]`
fn encode_nack(ranges: &[(u64, u16)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + ranges.len() * 10);
    buf.push(CTRL_NACK);
    buf.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
    for &(start, len) in ranges {
        buf.extend_from_slice(&start.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
    }
    buf
}

fn decode_nack(payload: &[u8]) -> Option<Vec<(u64, u16)>> {
    if payload.len() < 3 || payload[0] != CTRL_NACK {
        return None;
    }
    let count = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    let expected = 3 + count * 10;
    if payload.len() < expected {
        return None;
    }
    let mut ranges = Vec::with_capacity(count);
    let mut offset = 3;
    for _ in 0..count {
        let start = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());
        let len = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]);
        ranges.push((start, len));
        offset += 10;
    }
    Some(ranges)
}

/// 编码一条心跳：`[0xF2][u64 目前发到的最大计数器][u16 本端最近测得的入方向丢包率]`
///
/// 丢包率字段是给对端用的，不是自己看的：本端的"入方向丢包率"，从对端的
/// 视角看正是"它自己的出方向丢包率"——这正是对端决定自己该给发给我方的
/// 包补几份冗余时，唯一测得准的信号。见 [`PeerForwarder::current_tier`]
/// 的说明。
fn encode_heartbeat(highest: u64, loss_bp: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(11);
    buf.push(CTRL_HEARTBEAT);
    buf.extend_from_slice(&highest.to_be_bytes());
    buf.extend_from_slice(&loss_bp.to_be_bytes());
    buf
}

fn decode_heartbeat(payload: &[u8]) -> Option<(u64, u16)> {
    if payload.len() != 11 || payload[0] != CTRL_HEARTBEAT {
        return None;
    }
    let highest = u64::from_be_bytes(payload[1..9].try_into().unwrap());
    let loss_bp = u16::from_be_bytes(payload[9..11].try_into().unwrap());
    Some((highest, loss_bp))
}

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
/// 发送缓冲里的一条记录：发过什么、属于哪条流、什么时候发的。
///
/// `flow` 是 `None` 时（比如控制报文自己）不会驱动任何流的冗余升级，
/// 但仍然可以被 NACK 命中原样重发。
struct SentEntry {
    bytes: Vec<u8>,
    flow: Option<FlowKey>,
    sent_at: Instant,
}

/// 按计数器索引的发送缓冲，支持 O(1) 命中 + FIFO 淘汰。
///
/// 跟 [`FlowReplayTable`] 是同一个思路：`HashMap` 给查找，`VecDeque` 给淘汰顺序。
struct SendBuffer {
    entries: HashMap<u64, SentEntry>,
    order: VecDeque<u64>,
}

impl SendBuffer {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn push(&mut self, counter: u64, bytes: Vec<u8>, flow: Option<FlowKey>, now: Instant) {
        if self.order.len() >= SEND_BUFFER_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            counter,
            SentEntry {
                bytes,
                flow,
                sent_at: now,
            },
        );
        self.order.push_back(counter);
    }

    /// 命中且仍在 `deadline`（按当前连接 RTT 动态算，见 [`arq_deadline_for`]）
    /// 内才返回——超时的条目就算还在缓冲里也不给用，那时候重传已经没有意义了。
    fn get(&self, counter: u64, deadline: Duration) -> Option<&SentEntry> {
        self.entries
            .get(&counter)
            .filter(|e| e.sent_at.elapsed() < deadline)
    }
}

/// 一条内层流当前的冗余状态。
#[derive(Clone, Copy)]
struct RedundancyState {
    until: Instant,
    /// 额外补发的份数（不含原包）。1~8，对应总共 2~9 份，见 [`tier_for_bp`]。
    extra_copies: u8,
}

#[derive(Clone)]
struct PeerForwarder {
    conn: Connection,
    /// overlay 端到端加密。中继模式下 QUIC 是逐跳的，中继能看到明文，
    /// 机密性必须由这一层保证。
    crypto: Arc<SessionCrypto>,
    stats: PeerStats,
    /// 最近发送过的包，供 NACK 命中时原样重发；也用来把命中的计数器映射回
    /// 具体是哪条流，驱动那条流开启主动冗余。
    ///
    /// 用 `std::sync::Mutex` 而不是 `tokio::sync::Mutex`：`try_forward` 必须
    /// 保持同步、非阻塞（见其文档注释），临界区只是几次 map 操作、不跨
    /// `await`，用同步锁更轻。
    send_buffer: Arc<SyncMutex<SendBuffer>>,
    /// 每条内层流的冗余状态，只由 NACK 命中后精确开启——不是本连接的入方向
    /// 丢包就全连接一刀切。见 `handle_nack`。
    flow_redundancy: Arc<SyncMutex<HashMap<FlowKey, RedundancyState>>>,
    /// 目前为止发送过的最大计数器，心跳用来告诉对端"我发到哪了"。
    highest_sent: Arc<AtomicU64>,
    /// 本端最近一次测得的入方向丢包率（basis points，10000=100%）。
    ///
    /// 只用来往对端上报（塞进心跳里，见 [`encode_heartbeat`]），**不能**直接
    /// 拿来当自己的冗余基线用——这个数测的是"对端发给我"这个方向的丢包，
    /// 而 [`current_tier`](Self::current_tier) 要回答的是"我发给对端"这个
    /// 方向该补几份，两者是链路的两个独立方向，尤其在移动网络上可能差很多。
    measured_loss_bp: Arc<AtomicU16>,
    /// 连接级的**出方向**预测基线（0、2~8，见 [`tier_for_bp`]），决定新流量
    /// 该垫几份底。
    ///
    /// 这个值来自**对端心跳里上报的、对端测到的入方向丢包率**——也就是"我
    /// 发出去的包，对端那边实际收到的样子"，这才是预测"我该给自己发的包
    /// 补几份"时唯一测得准的方向。不能直接用本端自己的入方向丢包率
    /// （[`measured_loss_bp`] 字段那个）替代：两个方向的丢包率不保证对称，
    /// 用错方向会导致这条链路真正需要冗余的方向反而没测准。
    current_tier: Arc<AtomicU8>,
    /// 这条连接见过的最小 RTT（毫秒），拥塞判定的基线。`u64::MAX` 表示还
    /// 没有过任何样本。见 [`is_congested`]。
    min_rtt_ms: Arc<AtomicU64>,
    /// 补发流量速率限制的窗口状态：(当前窗口起始时间, 这个窗口已经用掉的
    /// 份数)。见 [`reserve_repair_budget`]。
    repair_budget: Arc<SyncMutex<(Instant, u32)>>,
    /// 因为发送队列没余量而被放弃的补发包数（累计）。见 [`Self::repair_has_room`]。
    ///
    /// **这个计数器是"副本挤掉原包"这个诊断的直接检验**：它在实测中频繁非零，
    /// 就说明补发流量确实一直在往一个已经排满的队列里挤；恒为零则说明诊断有偏差，
    /// 后续的控制器设计需要重新审视。
    repair_skipped_no_space: Arc<AtomicU64>,
    /// 因为发送队列没余量而被丢弃的**原包**数（累计）。见 `try_forward`。
    orig_dropped_queue_full: Arc<AtomicU64>,
}

impl PeerForwarder {
    /// 加密并投递一条控制报文（NACK / 心跳）。
    ///
    /// 复用跟数据报文完全相同的加密、计数器分配与重放窗口——不用另起一套
    /// 认证机制，控制报文也顺带享受重放保护和抗篡改。丢了不重传，靠上层
    /// 自己的周期性重复（心跳每秒一次、NACK 会在下一个空洞仍然存在时再发）
    /// 自愈。
    fn send_control(&self, payload: Vec<u8>) {
        match self.crypto.seal(&payload) {
            Ok(sealed) => {
                let _ = self.conn.send_datagram(sealed.into());
            }
            Err(e) => {
                debug!("[TUN] 控制报文加密失败: {}", e);
            }
        }
    }

    fn set_tier(&self, tier: u8) {
        self.current_tier.store(tier, Ordering::Relaxed);
    }

    /// 拿当前连接的 RTT 刷新历史最小值基线，并返回这一刻是否判定为拥塞。
    fn observe_congestion(&self) -> bool {
        let now_ms = self.conn.rtt().as_millis() as u64;
        let mut congested = false;
        let _ = self
            .min_rtt_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |min| {
                congested = is_congested(min, now_ms);
                Some(min.min(now_ms))
            });
        congested
    }

    /// 申请一份补发预算；申请不到就不该再发这一份补发包了。见
    /// [`reserve_repair_budget`]。
    fn try_reserve_repair_budget(&self) -> bool {
        let mut guard = self.repair_budget.lock().unwrap();
        let (allowed, window_start, used) = reserve_repair_budget(guard.0, guard.1, Instant::now());
        *guard = (window_start, used);
        allowed
    }

    /// 队列里还塞得下 `len` 字节的补发包吗？
    ///
    /// **这是整套机制里最关键的一道闸。** quinn 的数据报发送队列在满的时候
    /// 丢的是**最旧的**那个（`Connection::send_datagram` 传 `drop=true`
    /// → `pop_front()`），所以队列一满，后进来的副本会把还没发出去的**原包**
    /// 挤掉——修复机制亲手摧毁它要修复的东西。实测就是这样塌的：
    /// 副本挤掉原包 → 对端测到的丢包率不降反升 → 档位继续往上爬 → 越补越堵。
    ///
    /// `datagram_send_buffer_space()` 返回队列剩余空间，`> len` 就保证这次发送
    /// 不会挤掉任何已排队的报文。补发包在这里让路给原包，是因为**一个没发出去的
    /// 原包，比一个发出去的副本有价值得多**——副本的全部意义就是保住原包。
    fn repair_has_room(&self, len: usize) -> bool {
        self.conn.datagram_send_buffer_space() >= len
    }

    /// 收到对端的 NACK：命中的计数器原样从发送缓冲重发，并把命中的流标记为
    /// "需要冗余"，让后续该流的包自动补发，不用等下一次 NACK 才反应过来。
    fn handle_nack(&self, ranges: &[(u64, u16)]) {
        let deadline = arq_deadline_for(self.conn.rtt());
        let mut flows_to_activate: Vec<FlowKey> = Vec::new();
        // 一次 NACK 最多处理这么多个计数器。
        //
        // 区间长度是对端给的 `u16`，一个 1200 字节的数据报能塞进上百个区间，
        // 最坏情况是上百万次迭代——而这个循环**全程持有 `send_buffer` 互斥锁**、
        // 跑在接收热路径上，等于对端（或链路上任何能让报文通过认证的一方）
        // 可以直接把本端的转发通道拖死。发送缓冲本身只有
        // `SEND_BUFFER_CAP`(512) 条，扫超过这个量级纯属白扫。
        const MAX_NACK_COUNTERS_PER_MESSAGE: usize = 256;
        let mut scanned = 0usize;
        {
            let buffer = self.send_buffer.lock().unwrap();
            'outer: for &(start, count) in ranges {
                for counter in start..start.saturating_add(count as u64) {
                    if scanned >= MAX_NACK_COUNTERS_PER_MESSAGE {
                        debug!("[TUN] NACK 请求的计数器过多，截断处理");
                        break 'outer;
                    }
                    scanned += 1;
                    let Some(entry) = buffer.get(counter, deadline) else {
                        // 缓冲里没有（已经被淘汰或超过 ARQ 截止时间）——
                        // 放弃这个计数器，跟没收到 NACK 一样处理。
                        continue;
                    };
                    let len = entry.bytes.len();
                    // 跟主动冗余同一道闸：重传包也不能挤掉还没发出去的原包。
                    if !self.repair_has_room(len) {
                        self.repair_skipped_no_space.fetch_add(1, Ordering::Relaxed);
                        debug!("[TUN] 发送队列无余量，放弃重传 counter={}", counter);
                        continue;
                    }
                    if !self.try_reserve_repair_budget() {
                        // 补发预算已经用完——见 `MAX_REPAIR_PACKETS_PER_SEC`
                        // 的说明，这不是丢包，是主动放弃这次重传，避免补发
                        // 流量自己把链路打满。
                        debug!("[TUN] 补发预算已耗尽，放弃重传 counter={}", counter);
                        continue;
                    }
                    let conn = self.conn.clone();
                    let bytes = entry.bytes.clone();
                    tokio::spawn(async move {
                        match conn.send_datagram(bytes.into()) {
                            Ok(()) => {
                                // 抽样，理由同 `tx-repair`。
                                if counter % 1000 == 0 {
                                    tracing::info!("[TUN] tx-nack-resend counter={}", counter);
                                }
                            }
                            Err(e) => {
                                debug!("[TUN] NACK 重传失败 counter={}: {}", counter, e);
                            }
                        }
                    });
                    if let Some(flow) = entry.flow {
                        flows_to_activate.push(flow);
                    }
                }
            }
        }

        if flows_to_activate.is_empty() {
            return;
        }
        let tier = self.current_tier.load(Ordering::Relaxed).max(1);
        let until = Instant::now() + REDUNDANCY_HOLD;
        let mut fr = self.flow_redundancy.lock().unwrap();
        for flow in flows_to_activate {
            let was_active = fr
                .get(&flow)
                .map(|s| s.until > Instant::now())
                .unwrap_or(false);
            fr.insert(
                flow,
                RedundancyState {
                    until,
                    extra_copies: tier,
                },
            );
            if !was_active {
                tracing::info!(
                    "[TUN] 流(proto={} {}:{} -> {}:{}) 检测到丢包，开启主动冗余（{} 份，保持 {:?}）",
                    flow.protocol,
                    flow.source,
                    flow.source_port,
                    flow.destination,
                    flow.destination_port,
                    tier + 1,
                    REDUNDANCY_HOLD
                );
            }
        }
    }
}

/// 一个窗口至少要攒够这么多样本才结算。
///
/// 丢包率是抽样估计，方差随样本数下降。50 个样本时，真实 5% 的链路单窗口
/// 读数在 2%~8% 之间跳都属正常（标准误约 3 个百分点）。样本再少就纯粹是噪声，
/// 报出去只会让人追着假数字排查。
const MIN_LOSS_SAMPLES: u64 = 50;

/// 攒样本最多等这么久。稀疏流量下宁可报一个粗糙的数，也不能一直不报。
const MAX_LOSS_WINDOW: Duration = Duration::from_secs(10);

/// 基于 overlay 计数器空洞的**入方向**丢包测量。
///
/// 数据面从 TCP 代理迁到 TUN + DATAGRAM 之后，唯一还在上报的丢包口径是 QUIC
/// 的路径统计，而那测的是**出方向**。真正影响体验的"对端发来、我没收到"
/// 只能靠计数器空洞算——计数器是发送端在加密时打上的，中继换几段也不影响，
/// 天然是端到端、入方向的。
///
/// # 这个测量做不到什么
///
/// 它只能看见**落在已观测序号区间内**的空洞，因此：
///
/// - **尾部丢包看不见**：如果对端最后发的几个包全丢了，本端根本不知道那些序号
///   存在过。要补上这一块，需要对端在心跳里带上"我已发到第几号"。
/// - **分不清"对端没发"和"全丢了"**：两种情况本端观测到的都是"没有新序号"。
///   因此空闲窗口一律**不报**——报 100% 会在玩家静止时刷满假丢包。
/// - **不是精确值而是估计值**：见 [`MIN_LOSS_SAMPLES`]。
struct LossMeter {
    /// 本窗口见过的最大计数器
    highest: u64,
    /// 本窗口内首次见到的序号数
    received: u64,
    /// 本窗口的起始计数器
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

    fn on_received(&mut self, counter: u64, now: Instant) {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.window_start = counter;
            // 计时从**第一个包**算起，而不是从构造算起：
            // 否则连接刚建立那段空等也被算进窗口，首个读数会只有几个样本。
            self.window_began = now;
        }
        // 上一个窗口的迟到包不属于本窗口。计进来会稀释本窗口的丢包率，
        // 让真实丢包被"看起来收到了更多包"掩盖掉。
        if counter < self.window_start {
            return;
        }
        self.highest = self.highest.max(counter);
        self.received += 1;
    }

    /// 窗口到期且样本足够时结算，返回丢包率（万分之一）。
    ///
    /// 返回 `None` 表示**这次没有可信的观测**——可能是还没到期、样本不够，
    /// 或者链路空闲。绝不能把这些情况当成 0% 或 100%。
    fn poll(&mut self, now: Instant) -> Option<u16> {
        if !self.started {
            return None;
        }
        let elapsed = now.duration_since(self.window_began);
        if elapsed < LOSS_WINDOW {
            return None;
        }

        // 本窗口没有任何新序号：对端可能只是没发东西。
        // 这两种情况在本端是不可区分的，所以不报，并把计时重新开始。
        if self.received == 0 || self.highest < self.window_start {
            self.window_began = now;
            return None;
        }

        let span = self.highest - self.window_start + 1;
        // 样本不够就继续攒，不重置窗口——除非已经等得太久。
        if span < MIN_LOSS_SAMPLES && elapsed < MAX_LOSS_WINDOW {
            return None;
        }

        let received = self.received.min(span);
        let bp = (((span - received).saturating_mul(10_000)) / span).min(10_000) as u16;
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
        //
        // 这里是运行时逐包降级，不是接入连接时的一次性强校验——上一版实现
        // 在 attach_peer 里做过后者，一旦路径 MTU 探测还没跑完就整条连接拒收，
        // TUN 网卡装上了但什么都转发不了，见《抗丢包方案设计》第二节。
        // 这个校验必须一直保持"只丢这一个包"的形态，不能再收紧成"拒绝整条连接"。
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
        let counter = counter_of(&sealed);
        let len = sealed.len();

        // 补几份 = 连接级预测基线 与 这条流自己被 NACK 命中过的实测档位，
        // 取较大值（见 `effective_extra_copies`）。基线兜住"这条流还没机会
        // 自证丢没丢"的情况——ICMP ping 这种一次只发一个、隔很久才发下一个
        // 的稀疏流，靠自己触发一次 NACK 可能要等将近一个心跳周期，等不起。
        let flow = Ipv4Header::from_bytes(packet).map(|h| flow_key(h, packet));
        let flow_specific = flow.and_then(|f| {
            let fr = self.flow_redundancy.lock().unwrap();
            fr.get(&f)
                .filter(|s| s.until > Instant::now())
                .map(|s| s.extra_copies)
        });
        let extra_copies =
            effective_extra_copies(self.current_tier.load(Ordering::Relaxed), flow_specific);
        // 冗余份必须复用这份密文字节原样重发，不能对同一个包再调一次
        // `crypto.seal()`——那样会拿到不同计数器的两个包，现有重放窗口就
        // 没法把它们当成同一个包去重了。只有确定要发冗余份时才克隆，
        // 干净链路上这里零额外开销。
        let redundant_bytes = (extra_copies > 0).then(|| sealed.clone());

        // 队列满时**丢当前这个包**，而不是让 quinn 去丢最旧的那个。
        //
        // quinn 的 `send_datagram` 满队列时执行 `pop_front()`（丢最旧），这是最差的
        // 队列管理策略：它把已经排了很久、马上就要发出去的包丢掉，最大化每个真正
        // 通过的包的延迟，还会摧毁内层 TCP 的 RTT 采样，把平滑过载变成突发超时。
        // 改成丢最新（尾丢）之后，内层 TCP 能对着隧道的真实容量正常收敛，
        // 而且我们顺带拿到一个精确的自挤占计数器——这个数非零就直接证明
        // "我们自己是丢包来源"，不需要任何推断或对端往返。
        if self.conn.datagram_send_buffer_space() < len {
            self.orig_dropped_queue_full.fetch_add(1, Ordering::Relaxed);
            debug!(
                "[TUN] 发送队列已满，丢弃原包 counter={} bytes={}",
                counter, len
            );
            return false;
        }

        // 记进发送缓冲，供后续命中 NACK 时原样重发；同时刷新心跳要带的
        // "最大计数器"。必须在真正调用 send_datagram 之前记，晚了的话
        // 一个几乎同时到达的 NACK 会查不到刚发出去的这个计数器。
        self.send_buffer
            .lock()
            .unwrap()
            .push(counter, sealed.clone(), flow, Instant::now());
        self.highest_sent.fetch_max(counter, Ordering::Relaxed);

        let sent = match self.conn.send_datagram(sealed.into()) {
            Ok(()) => {
                // 数据面迁到 DATAGRAM 之后，这个埋点一直没跟着迁过来，
                // 于是不管传多少数据带宽都显示 0。
                if let Some((stats, user)) = &self.stats {
                    let (stats, user) = (stats.clone(), user.clone());
                    tokio::spawn(async move { stats.record_send(&user, len).await });
                }
                // 这条本来每个包都无条件打一次，联机跑图时一秒上千个包
                // 就是一秒上千次同步日志 I/O，直接卡在转发热路径里——
                // 这是"大量发包时 ping 从 40ms 飙到 1300ms"的真正原因，
                // 日志系统本身也已经改成非阻塞（见 `logging.rs`），但源头
                // 该抽样还是要抽样，跟 `rx`/`tx` 两条日志保持同一个策略。
                if counter <= 100 || counter % 1000 == 0 {
                    tracing::info!("[TUN] tx-orig counter={} bytes={}", counter, len);
                }
                true
            }
            Err(e) => {
                debug!("[TUN] 数据报发送失败: {}", e);
                false
            }
        };

        // 只在原包真的发出去之后才补冗余份——原包都没发出去，补一份没意义。
        if sent {
            if let Some(bytes) = redundant_bytes {
                let conn = self.conn.clone();
                let stats = self.stats.clone();
                // 克隆整个 forwarder（内部都是 Arc，克隆很轻）只是为了在
                // 这个后台任务里也能申请补发预算——不能省，见
                // `MAX_REPAIR_PACKETS_PER_SEC` 的说明：这道闸门必须卡在
                // "实际要发出去"这一刻，不能只在 try_forward 这次调用的
                // 决策时刻查一次，因为同一秒里还有别的包也在各自的后台
                // 任务里排队发补发份，只有在真正发送前查预算才挡得住
                // 大家加起来的总量。
                let forwarder = self.clone();
                tokio::spawn(async move {
                    for i in 0..extra_copies {
                        tokio::time::sleep(redundancy_delay_for(i, extra_copies)).await;
                        // 队列没地方了就整串放弃——绝不能让副本挤掉还没发出去的
                        // 原包，见 `repair_has_room`。这一条必须在预算检查之前：
                        // 预算管的是"发太多会不会触发运营商风控"，这一条管的是
                        // "这一份会不会直接害死一个原包"，后者更硬。
                        if !forwarder.repair_has_room(len) {
                            forwarder
                                .repair_skipped_no_space
                                .fetch_add(1, Ordering::Relaxed);
                            debug!(
                                "[TUN] 发送队列无余量，放弃剩余冗余份 counter={} copy={}/{}",
                                counter,
                                i + 1,
                                extra_copies
                            );
                            break;
                        }
                        if !forwarder.try_reserve_repair_budget() {
                            debug!(
                                "[TUN] 补发预算已耗尽，放弃剩余冗余份 counter={} copy={}/{}",
                                counter,
                                i + 1,
                                extra_copies
                            );
                            break;
                        }
                        match conn.send_datagram(bytes.clone().into()) {
                            Ok(()) => {
                                if let Some((stats, user)) = &stats {
                                    let (stats, user) = (stats.clone(), user.clone());
                                    tokio::spawn(
                                        async move { stats.record_send(&user, len).await },
                                    );
                                }
                                // 抽样：跟 `tx-orig` 保持同一个策略。这条本来是
                                // 每份补包都无条件打一次，最高 300 条/秒，而且
                                // 偏偏在链路已经出问题时才触发——`tx-orig` 那边
                                // 的注释早就写明"每包无条件打日志是大量发包时
                                // ping 从 40ms 飙到 1300ms 的真正原因"，当时只修了
                                // 原包路径，补发路径漏掉了。
                                if counter % 1000 == 0 {
                                    tracing::info!(
                                        "[TUN] tx-repair counter={} bytes={} copy={}/{}",
                                        counter,
                                        len,
                                        i + 1,
                                        extra_copies
                                    );
                                }
                            }
                            Err(e) => {
                                debug!(
                                    "[TUN] 补包发送失败 counter={} copy={}/{}: {}",
                                    counter,
                                    i + 1,
                                    extra_copies,
                                    e
                                );
                            }
                        }
                    }
                });
            }
        }

        sent
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
            send_buffer: Arc::new(SyncMutex::new(SendBuffer::new())),
            flow_redundancy: Arc::new(SyncMutex::new(HashMap::new())),
            highest_sent: Arc::new(AtomicU64::new(0)),
            measured_loss_bp: Arc::new(AtomicU16::new(0)),
            // 从 0 起步（不预设有损）：真实档位由对端心跳汇报的丢包率
            // （`set_tier`，见那里的说明）来定，收到第一条心跳之前不补冗余。
            current_tier: Arc::new(AtomicU8::new(0)),
            min_rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
            repair_budget: Arc::new(SyncMutex::new((Instant::now(), 0))),
            repair_skipped_no_space: Arc::new(AtomicU64::new(0)),
            orig_dropped_queue_full: Arc::new(AtomicU64::new(0)),
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

        // 每秒把"目前发到的最大计数器"告诉对端，让它能发现尾部丢包——
        // 最后几个包全丢的话，没有后续包能暴露这个空洞，只能靠心跳。
        // 连接关掉之后 `send_datagram` 会持续报错，靠这个自然退出，
        // 不需要额外的取消信号。
        {
            let heartbeat = forwarder.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                    if heartbeat.conn.close_reason().is_some() {
                        break;
                    }
                    let highest = heartbeat.highest_sent.load(Ordering::Relaxed);
                    let loss_bp = heartbeat.measured_loss_bp.load(Ordering::Relaxed);
                    heartbeat.send_control(encode_heartbeat(highest, loss_bp));
                }
            });
        }

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
    ///
    /// 判定和记账是 [`ReplayWindow::check_and_set`] 里的一次调用，不是
    /// "先问一次再记一次"——那个拆分正是环形位图绕回缺陷的根源，见该函数
    /// 的文档。这里也不要再把它拆回两步。
    fn accept(&mut self, key: FlowKey, counter: u64) -> ReplayVerdict {
        if !self.windows.contains_key(&key) {
            if self.windows.len() >= MAX_TRACKED_FLOWS {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.windows.remove(&oldest);
                }
            }
            self.windows.insert(key, ReplayWindow::new());
            self.insertion_order.push_back(key);
        }
        let window = self.windows.get_mut(&key).expect("刚插入过，一定存在");
        window.check_and_set(counter)
    }
}

/// 同一条连接上连续这么多个数据报被重放判定拒收，就升级成 WARN。
///
/// 健康链路上这是结构性不可能的：真实的网络重复/乱序不会连成一片，而
/// 冗余补发份最多也就 [`MAX_EXTRA_COPIES`] 份。连续拒收几十个只可能是
/// 本端判定逻辑自己出了问题——上一次环形位图绕回时，这条日志停在 DEBUG
/// 级、又跟正常的偶发重复混在一起，于是"本端把自己锁死"看起来像"网络在
/// 丢包"，白白多绕了两轮排查。
const REPLAY_REJECT_ALARM: u32 = 64;

/// 跟踪本端观测到、但还没到达的计数器，驱动 NACK 请求重传。
///
/// 计数器是本连接**全局**的（`crypto.rs` 里 `SessionCrypto` 只有一个
/// `tx_counter`，不分流），所以这里也不分流——分流靠的是发送端自己的
/// [`SendBuffer`]，NACK 只管"这个计数器要不要重发"，回填哪条流是发送端
/// 命中缓冲之后才知道的事。
struct GapTracker {
    highest_processed: u64,
    /// 还没见过任何计数器。不能用 `highest_processed == 0` 代替：0 是合法计数器
    /// （`crypto.rs` 的 `tx_counter` 从 0 开始），分不清"没开始"和"收到了 0 号"。
    started: bool,
    /// 计数器 -> 首次发现缺失的时间
    pending: HashMap<u64, Instant>,
    last_nack: Option<Instant>,
}

impl GapTracker {
    fn new() -> Self {
        Self {
            highest_processed: 0,
            started: false,
            pending: HashMap::new(),
            last_nack: None,
        }
    }

    /// 收到一个已解密、已认证的计数器就调用——不管内容是数据还是控制报文，
    /// 目的只是记录"这个序号存在过"。
    ///
    /// **返回这个计数器是不是首次见到。** 调用方必须用这个返回值给
    /// [`LossMeter::on_received`] 把门：冗余副本携带的是**同一个计数器**
    /// （这是设计要求，见《抗丢包方案设计》第三节），15~60ms 后到达时仍落在
    /// 同一个统计窗口内。如果每次到达都计入收包数，补 k 份时实测丢包率会恒为 0
    /// 直到单次传输丢包率超过 `k/(k+1)`——k=2 就是 67%，等于把整个自适应闭环
    /// 变成一个 67% 才动作的开关。这正是《踩坑记录》第九条记录过、
    /// 而实现里又违反了的坑。
    fn observe(&mut self, counter: u64, now: Instant) -> bool {
        if !self.started {
            // 从第一个真正见到的计数器起步，而不是从 0 起步——否则首个计数器
            // 若不是 0，`0..counter` 会被整段当成空洞灌进 `pending`，
            // 凭空造出一批不存在的丢包去 NACK。
            self.started = true;
            self.highest_processed = counter;
            return true;
        }
        if self.pending.remove(&counter).is_some() {
            // 补上了一个已知空洞：是首次见到。
            return true;
        }
        if counter > self.highest_processed {
            for missing in (self.highest_processed + 1)..counter {
                self.pending.entry(missing).or_insert(now);
            }
            self.highest_processed = counter;
            return true;
        }
        // 走到这里只可能是：冗余副本 / NACK 重传的重复到达，或早已处理过的旧号。
        false
    }

    /// 到了该发 NACK 的时候，取出当前该催的空洞（过了重排容忍期、
    /// 还没过 `deadline`），按连续区间压缩，最多带 [`NACK_MAX_RANGES`] 个。
    /// 超过截止时间的空洞直接放弃，不再纳入统计。
    ///
    /// `deadline` 由调用方按当前连接的实测 RTT 算好传进来（见
    /// [`arq_deadline_for`]）——固定 RTT 越高的链路越需要更长的截止时间，
    /// 写死一个值在高延迟链路上会导致空洞在 NACK 发出去之前就被这里放弃。
    fn ranges_to_nack(&mut self, now: Instant, deadline: Duration) -> Vec<(u64, u16)> {
        if let Some(last) = self.last_nack {
            if now.duration_since(last) < NACK_MIN_INTERVAL {
                return Vec::new();
            }
        }
        self.pending
            .retain(|_, first_seen| now.duration_since(*first_seen) < deadline);

        let mut due: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, first_seen)| now.duration_since(**first_seen) >= REORDER_GRACE)
            .map(|(c, _)| *c)
            .collect();
        if due.is_empty() {
            return Vec::new();
        }
        due.sort_unstable();

        let mut ranges = Vec::new();
        let mut start = due[0];
        let mut len: u16 = 1;
        for &c in &due[1..] {
            if c == start + len as u64 && len < u16::MAX {
                len += 1;
            } else {
                ranges.push((start, len));
                if ranges.len() >= NACK_MAX_RANGES {
                    self.last_nack = Some(now);
                    return ranges;
                }
                start = c;
                len = 1;
            }
        }
        ranges.push((start, len));
        self.last_nack = Some(now);
        ranges
    }
}

fn maybe_send_nack(sender: &PeerForwarder, gaps: &mut GapTracker, now: Instant) {
    let deadline = arq_deadline_for(sender.conn.rtt());
    let ranges = gaps.ranges_to_nack(now, deadline);
    if !ranges.is_empty() {
        sender.send_control(encode_nack(&ranges));
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
    let mut gaps = GapTracker::new();
    // 见 `REPLAY_REJECT_ALARM`。放在收包循环里而不是按流记：控制报文走的是
    // 另一条分支，不会打断计数，所以这个数就是"连续多少个数据报没能通过
    // 重放判定"，正是要报警的那个信号。
    let mut consecutive_rejects: u32 = 0;
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

        let now = Instant::now();
        // 空洞跟踪和丢包率统计都不分数据/控制报文——两者共用同一个计数器序列
        // （`crypto.rs` 的 `tx_counter` 是连接全局的，不区分内容），控制报文
        // 一样要算进"这个序号收到了"。**必须在下面的控制报文分支之前做**：
        // 心跳每秒占用一个计数器，如果只对数据报文调用 `loss.on_received`，
        // 心跳占的那个号会被 `LossMeter` 永远当成"没收到"算进丢包率——
        // 等于自己制造假丢包，还会被当成真信号触发冗余升级/误导排查。
        //
        // 只有**首次见到**的计数器才计入收包数。冗余副本带的是同一个计数器，
        // 重复计数会把实测丢包率稀释成 0，见 `GapTracker::observe` 的说明。
        let first_sighting = gaps.observe(counter, now);
        if first_sighting {
            loss.on_received(counter, now);
        }
        if let Some(bp) = loss.poll(now) {
            if let Some((stats, user)) = &sender.stats {
                let (stats, user) = (stats.clone(), user.clone());
                tokio::spawn(async move { stats.update_inbound_loss(&user, bp).await });
            }
            if bp > 0 {
                tracing::info!("[TUN] 入方向丢包 {:.2}%", bp as f64 / 100.0);
            }
            // 存下来给对端用（塞进下一条心跳），**不**在这里直接拿去设
            // `current_tier`——这个 bp 测的是"对端发给我"这个方向，
            // 而 `current_tier` 要回答的是"我发给对端"该补几份，
            // 那个数只能靠对端心跳汇报，见 `current_tier` 字段的说明。
            sender.measured_loss_bp.store(bp, Ordering::Relaxed);
        }

        // 控制报文（NACK/心跳）不是 IP 包，标签取值故意避开合法 IPv4 首字节
        // （版本号固定是 4），解密后不用再包一层信封就能跟数据报文分开，
        // 走独立分支处理，不进入下面的重放判定/TUN 写入流程。
        if let Some(&tag) = packet.first() {
            if !looks_like_ipv4(tag) {
                match tag {
                    CTRL_NACK => {
                        if let Some(ranges) = decode_nack(&packet) {
                            sender.handle_nack(&ranges);
                        } else {
                            debug!("[TUN] 收到格式错误的 NACK");
                        }
                    }
                    CTRL_HEARTBEAT => {
                        if let Some((highest, remote_loss_bp)) = decode_heartbeat(&packet) {
                            // 只为暴露尾部空洞（对端说它发到哪了），这个号本身
                            // 并没有真的到达本端，**不能**计入收包数——所以这里
                            // 明确丢弃返回值，不喂给 `LossMeter`。
                            let _ = gaps.observe(highest, now);
                            // 对端汇报的是它自己的入方向丢包率，正好等于
                            // "我发给它"这个方向的丢包率——这是设出方向
                            // 预测基线唯一测得准的信号，见 `current_tier`
                            // 字段的说明。
                            let tier = tier_for_bp(remote_loss_bp);
                            // 但在往上抬档位之前，先看链路是不是已经在拥塞：
                            // 如果这次丢包本身就是排队/拥塞造成的，再往上
                            // 加冗余只会让拥塞更重，见 `CONGESTION_RTT_
                            // MULTIPLIER` 的说明。
                            let tier = if sender.observe_congestion() {
                                tier.min(CONGESTED_TIER_CAP)
                            } else {
                                tier
                            };
                            sender.set_tier(tier);
                        } else {
                            debug!("[TUN] 收到格式错误的心跳");
                        }
                    }
                    _ => {
                        debug!("[TUN] 未知控制报文标签: 0x{:02x}", tag);
                    }
                }
                maybe_send_nack(&sender, &mut gaps, now);
                continue;
            }
        }

        let len = packet.len();
        if !(20..=MAX_PACKET).contains(&len) {
            debug!("[TUN] 丢弃长度异常的包: {}", len);
            maybe_send_nack(&sender, &mut gaps, now);
            continue;
        }
        let Some(header) = Ipv4Header::from_bytes(&packet) else {
            maybe_send_nack(&sender, &mut gaps, now);
            continue;
        };
        // 重放判定按内层流拆分，必须在拿到明文之后做——五元组在解密前不可见。
        let key = flow_key(header, &packet);
        match flows.accept(key, counter) {
            ReplayVerdict::Fresh => consecutive_rejects = 0,
            verdict => {
                consecutive_rejects += 1;
                // 两种拒绝原因分开报，并带上窗口状态：`counter` 明显比
                // `highest` 新却报重复，就只可能是环形位图绕回。
                match verdict {
                    ReplayVerdict::Duplicate { highest, slot } => debug!(
                        "[TUN] 丢弃重复的 overlay 报文 (counter={counter}, 流内最大={highest}, 槽位={slot})"
                    ),
                    ReplayVerdict::TooOld { highest, floor } => debug!(
                        "[TUN] 丢弃过旧的 overlay 报文 (counter={counter}, 流内最大={highest}, 窗口下沿={floor})"
                    ),
                    ReplayVerdict::Fresh => unreachable!("放行的分支在上面"),
                }
                if consecutive_rejects == REPLAY_REJECT_ALARM {
                    warn!(
                        "[TUN] 已连续 {} 个数据报被重放判定拒收 — 健康链路上这不可能，\
                         八成是本端判定逻辑出了问题 (最近一次: counter={counter}, {:?})",
                        consecutive_rejects, verdict
                    );
                }
                maybe_send_nack(&sender, &mut gaps, now);
                continue;
            }
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
            maybe_send_nack(&sender, &mut gaps, now);
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
        maybe_send_nack(&sender, &mut gaps, now);
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

    /// 只关心"这个包放行没有"的测试用它，丢掉拒绝原因。
    fn passes(table: &mut FlowReplayTable, key: FlowKey, counter: u64) -> bool {
        table.accept(key, counter) == ReplayVerdict::Fresh
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
        assert!(passes(&mut table, quiet, 10));

        // 突发流把会话计数器推得很远——远超单个窗口宽度
        for c in 100..100_000u64 {
            table.accept(bursty, c);
        }

        // 安静流随后到达的包仍然必须被接受
        assert!(
            passes(&mut table, quiet, 11),
            "突发流量不得让安静流的后续包被判成过旧"
        );
        // 它自己的重复包照样要拒
        assert!(!passes(&mut table, quiet, 11), "同一条流内的重复仍要拒绝");
    }

    /// 一条长命流连续跑过环形位图的整圈边界后，必须还能继续收包。
    ///
    /// 这是 `crypto.rs` 里那个绕回缺陷在**调用侧**的回归测试：那次实机故障
    /// 就是这条路径——Minecraft 那条 TCP 流一直用同一个五元组，累计计数器
    /// 跨过 65536 之后，本端把它之后的每一个包都判成重复，游戏 reset。
    #[test]
    fn a_long_lived_flow_survives_crossing_the_replay_ring() {
        let mut table = FlowReplayTable::new();
        let game = key(25565);
        // 走满两圈多，覆盖第一次绕回和之后的稳态。
        for c in 0..(2 * 65536u64 + 1000) {
            assert!(
                passes(&mut table, game, c),
                "长命流跨圈之后被误判 (counter={c})"
            );
        }
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
        assert!(passes(&mut table, icmp, 5));
        assert!(
            passes(&mut table, udp, 5),
            "不同协议是不同的流，不该互相判重放"
        );
    }

    /// 入方向丢包：计数器空洞就是丢的包
    #[test]
    fn loss_meter_measures_counter_gaps() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        // 0..200 只收到偶数，即丢一半
        for c in (0..200u64).step_by(2) {
            m.on_received(c, t);
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
        for c in 0..200u64 {
            m.on_received(c, t);
        }
        assert_eq!(m.poll(t + LOSS_WINDOW), Some(0));
    }

    /// 冗余副本**不得**计入收包数。
    ///
    /// 副本按设计携带同一个计数器，15~60ms 后到达、仍落在同一个统计窗口内。
    /// 一旦每次到达都 `received += 1`，`poll` 里的 `received.min(span)` 会把
    /// 丢包率一路吃到 0——补 k 份时实测丢包率恒为 0 直到单次传输丢包率超过
    /// `k/(k+1)`（k=2 即 67%）。整个自适应闭环退化成一个 67% 才动作的开关，
    /// 而且**所有**用来验证补包效果的测量都经过这个仪器，一并失真。
    /// 这是《踩坑记录》第九条记录过、实现里又违反了的坑。
    ///
    /// 这里连同 `GapTracker` 一起测，因为首次判定是它给的。
    #[test]
    fn loss_meter_ignores_redundant_copies() {
        let t = Instant::now();
        let mut gaps = GapTracker::new();
        let mut m = LossMeter::new(t);

        // 0..200 只有偶数真的到了（丢一半），且每个到达的包都额外收到 2 份副本
        // ——正是 k=2 时链路上的样子。
        for c in (0..200u64).step_by(2) {
            for _copy in 0..3 {
                if gaps.observe(c, t) {
                    m.on_received(c, t);
                }
            }
        }

        let bp = m.poll(t + LOSS_WINDOW).expect("窗口到期应结算");
        assert!(
            (4800..=5100).contains(&bp),
            "丢一半仍应报 ~50%，副本不得稀释；实得 {}bp（0 就说明又被副本致盲了）",
            bp
        );
    }

    /// 首个计数器不为 0 时，不能把 `0..counter` 整段当成空洞。
    ///
    /// 否则连接一建立就凭空造出一批不存在的丢包去 NACK，既污染丢包率
    /// 又白白触发补发。
    #[test]
    fn gap_tracker_does_not_invent_gaps_before_the_first_counter() {
        let t = Instant::now();
        let mut gaps = GapTracker::new();
        assert!(gaps.observe(5000, t), "首个计数器必须算首次见到");
        assert!(
            gaps.ranges_to_nack(t + REORDER_GRACE * 2, ARQ_DEADLINE_CEILING)
                .is_empty(),
            "首个计数器之前的号从未存在过，不该被当成空洞"
        );
    }

    /// **空闲不是丢包。**
    ///
    /// 本端观测到"没有新序号"时，无法区分对端没发和全丢了。此前的实现会
    /// 直接报 100%，于是玩家一站着不动、一开菜单，界面就刷满假丢包。
    #[test]
    fn idle_link_must_not_be_reported_as_total_loss() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        for c in 0..200u64 {
            m.on_received(c, t);
        }
        assert_eq!(m.poll(t + LOSS_WINDOW), Some(0), "先正常结算一次");

        // 之后对端安静下来，一个包都不发
        let idle = t + LOSS_WINDOW * 3;
        assert_eq!(m.poll(idle), None, "空闲窗口不得报成 100% 丢包");
        assert_eq!(m.poll(idle + LOSS_WINDOW * 2), None, "持续空闲同样不报");
    }

    /// 样本太少时估计的方差比数值本身还大，不能报
    #[test]
    fn loss_meter_needs_enough_samples() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        for c in 0..5u64 {
            m.on_received(c, t);
        }
        assert_eq!(
            m.poll(t + LOSS_WINDOW),
            None,
            "5 个样本算出的丢包率纯粹是噪声"
        );
        // 攒够之后才结算
        for c in 5..MIN_LOSS_SAMPLES + 5 {
            m.on_received(c, t);
        }
        assert!(m.poll(t + LOSS_WINDOW).is_some(), "样本够了就该结算");
    }

    /// 稀疏流量下不能永远攒不够就一直不报
    #[test]
    fn loss_meter_settles_eventually_even_when_sparse() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        for c in 0..5u64 {
            m.on_received(c, t);
        }
        assert!(
            m.poll(t + MAX_LOSS_WINDOW).is_some(),
            "等得够久就该报，哪怕样本少"
        );
    }

    /// 上一个窗口的迟到包会稀释本窗口的丢包率，必须排除
    #[test]
    fn late_packets_from_the_previous_window_are_ignored() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        for c in 0..200u64 {
            m.on_received(c, t);
        }
        m.poll(t + LOSS_WINDOW);

        // 新窗口：201..400 丢一半，同时混入几个上个窗口的迟到包
        let t2 = t + LOSS_WINDOW;
        for c in (201..400u64).step_by(2) {
            m.on_received(c, t2);
        }
        for late in [3u64, 17, 42] {
            m.on_received(late, t2);
        }
        let bp = m.poll(t2 + LOSS_WINDOW).expect("应结算");
        assert!(
            (4700..=5200).contains(&bp),
            "迟到包不该把丢包率冲淡，实得 {}bp",
            bp
        );
    }

    /// 窗口没到期不该结算
    #[test]
    fn loss_meter_waits_for_the_window() {
        let t = Instant::now();
        let mut m = LossMeter::new(t);
        m.on_received(0, t);
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

    /// 控制报文的标签必须避开合法 IPv4 首字节（版本号固定占高 4 位 = 4），
    /// 否则控制报文可能被误当成 IP 包处理，或者真实 IP 包被误当成控制报文吞掉。
    #[test]
    fn control_tags_never_look_like_ipv4() {
        assert!(!looks_like_ipv4(CTRL_NACK));
        assert!(!looks_like_ipv4(CTRL_HEARTBEAT));
        // 标准 20 字节头（IHL=5）到最大 60 字节头（IHL=15）覆盖的全部合法首字节
        for ihl in 5..=15u8 {
            let first_byte = (4 << 4) | ihl;
            assert!(
                looks_like_ipv4(first_byte),
                "0x{:02x} 应该被认成合法 IPv4",
                first_byte
            );
        }
    }

    #[test]
    fn nack_roundtrips_through_encode_decode() {
        let ranges = vec![(100u64, 3u16), (500u64, 1u16), (9999u64, 64u16)];
        let encoded = encode_nack(&ranges);
        let decoded = decode_nack(&encoded).expect("应该能解出来");
        assert_eq!(decoded, ranges);
    }

    #[test]
    fn nack_decode_rejects_truncated_payload() {
        let ranges = vec![(1u64, 5u16), (2u64, 5u16)];
        let mut encoded = encode_nack(&ranges);
        encoded.truncate(encoded.len() - 1);
        assert!(
            decode_nack(&encoded).is_none(),
            "长度对不上必须拒绝，不能越界读"
        );
    }

    #[test]
    fn nack_decode_rejects_wrong_tag() {
        let mut encoded = encode_nack(&[(1, 1)]);
        encoded[0] = CTRL_HEARTBEAT;
        assert!(decode_nack(&encoded).is_none());
    }

    #[test]
    fn heartbeat_roundtrips_through_encode_decode() {
        let encoded = encode_heartbeat(123_456_789, 4321);
        assert_eq!(decode_heartbeat(&encoded), Some((123_456_789, 4321)));
    }

    #[test]
    fn heartbeat_decode_rejects_wrong_tag_or_length() {
        assert!(decode_heartbeat(&[CTRL_NACK, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]).is_none());
        assert!(decode_heartbeat(&[CTRL_HEARTBEAT, 0, 0]).is_none());
    }

    /// 分档曲线：<0.2% 不补，0.2~5% 补 1 份，5%+ 补 2 份封顶。
    ///
    /// **关键回归：微量丢包不得触发加码。** 旧表在 `bp >= 1`（0.01%）时就直接跳到
    /// 2 份额外拷贝，也就是流量立刻三倍；而 0.1~0.5% 的丢包在公网上完全正常。
    /// 那个悬崖是"越补越堵 → 连接超时"正反馈环的起点，实测 macOS↔Windows 和
    /// Windows↔Windows 都会复现，纯单倍包时代从未出现过。
    #[test]
    fn redundancy_tier_matches_the_design_thresholds() {
        assert_eq!(tier_for_bp(0), 0);
        // 微量丢包必须**不**触发任何补发——这一条是防止悬崖复活的守卫。
        assert_eq!(tier_for_bp(1), 0, "0.01% 丢包不该触发补发");
        assert_eq!(tier_for_bp(19), 0, "0.19% 丢包不该触发补发");
        assert_eq!(tier_for_bp(20), 1);
        assert_eq!(tier_for_bp(500), 1);
        assert_eq!(tier_for_bp(501), MAX_EXTRA_COPIES);
        assert_eq!(tier_for_bp(10_000), MAX_EXTRA_COPIES);
        // 上限本身不得回退到那个靠伪造引用授权的 8。
        assert_eq!(MAX_EXTRA_COPIES, 2, "补发份数上限不得超过 2");
    }

    /// 份数少时维持原来的固定错峰间隔；份数多到会把最后一份推过
    /// `REDUNDANCY_WINDOW_CAP` 时，间隔要压缩，保证全部补发都挤在窗口内。
    #[test]
    fn redundancy_delay_stays_within_the_window_cap_as_copies_grow() {
        // 份数少：维持原来的固定 10ms 间隔，行为不变。
        assert_eq!(redundancy_delay_for(0, 2), REDUNDANCY_DELAY);
        assert_eq!(
            redundancy_delay_for(1, 2),
            REDUNDANCY_DELAY + REDUNDANCY_STAGGER
        );

        // 封顶的 8 份：最后一份（i=7）不能晚于窗口上限。
        let last = redundancy_delay_for(MAX_EXTRA_COPIES - 1, MAX_EXTRA_COPIES);
        assert!(last <= REDUNDANCY_WINDOW_CAP);
        // 但补发依旧要保持错峰（不能全挤到同一时刻，不然一次突发丢包
        // 会把所有份数一起带走，冗余等于白加）。
        assert!(
            redundancy_delay_for(1, MAX_EXTRA_COPIES) > redundancy_delay_for(0, MAX_EXTRA_COPIES)
        );
    }

    /// 还没有过任何 RTT 样本时不能瞎判定拥塞——第一次心跳到达前，基线是
    /// `u64::MAX`，任何 RTT 都不该被当成"偏离基线"。
    #[test]
    fn congestion_detection_needs_a_baseline_first() {
        assert!(!is_congested(u64::MAX, 500));
    }

    /// 没超过 `CONGESTION_RTT_MULTIPLIER` 倍基线不算拥塞，超过了才算——
    /// 边界值精确到刚好等于倍数那一下不算（用的是 `>`，不是 `>=`）。
    #[test]
    fn congestion_detection_triggers_only_past_the_multiplier() {
        assert!(!is_congested(30, 30 * CONGESTION_RTT_MULTIPLIER as u64));
        assert!(is_congested(30, 30 * CONGESTION_RTT_MULTIPLIER as u64 + 1));
    }

    /// 补发预算在上限内一直放行，一超过上限就该拒绝。
    #[test]
    fn repair_budget_allows_up_to_the_cap_then_blocks() {
        let start = Instant::now();
        let mut window_start = start;
        let mut used = 0u32;
        for _ in 0..MAX_REPAIR_PACKETS_PER_SEC {
            let (allowed, ws, u) = reserve_repair_budget(window_start, used, start);
            assert!(allowed, "没到上限之前都该放行");
            window_start = ws;
            used = u;
        }
        let (allowed, ..) = reserve_repair_budget(window_start, used, start);
        assert!(!allowed, "超过每秒上限之后必须拒绝，这是最后一道硬闸门");
    }

    /// 窗口过期（超过 1 秒）之后必须重新放行，不能被上一个窗口的旧计数
    /// 卡死——链路缓过来之后补发不该被永久掐断。
    #[test]
    fn repair_budget_resets_after_the_window_expires() {
        let start = Instant::now();
        let later = start + Duration::from_millis(1001);
        let (allowed, window_start, used) =
            reserve_repair_budget(start, MAX_REPAIR_PACKETS_PER_SEC, later);
        assert!(allowed, "窗口过期后应该重新放行，不能被旧窗口的计数卡住");
        assert_eq!(used, 1);
        assert_eq!(window_start, later);
    }

    /// 预测基线兜底、探测针实测只会往上修正，不会盖过更新鲜的基线。
    #[test]
    fn effective_extra_copies_takes_the_larger_of_baseline_and_flow_specific() {
        // 没测出来过丢包、这条流也没被 NACK 命中过：不多发。
        assert_eq!(effective_extra_copies(0, None), 0);
        // 连接级已经测出在丢包，这条流还没机会自证——按基线垫底。
        assert_eq!(effective_extra_copies(2, None), 2);
        // 这条流被探测针命中过，但基线更高（链路刚变得更差）：以更新鲜的基线为准。
        assert_eq!(effective_extra_copies(3, Some(1)), 3);
        // 这条流被命中的实测档位比基线还高：以实测为准（探测针只会往上修）。
        assert_eq!(effective_extra_copies(1, Some(3)), 3);
        // 链路已经干净（基线回到 0），但这条流之前被命中过、redundancy 状态
        // 还没过期：仍然保留这条流自己的实测保护，直到状态自然过期。
        assert_eq!(effective_extra_copies(0, Some(2)), 2);
    }

    #[test]
    fn gap_tracker_ignores_reordering_within_grace_period() {
        let t = Instant::now();
        let mut g = GapTracker::new();
        g.observe(1, t);
        g.observe(3, t); // 2 还没到，但可能只是乱序
        assert!(
            g.ranges_to_nack(t, ARQ_DEADLINE_FLOOR).is_empty(),
            "重排容忍期内不该立刻 NACK"
        );
        // 2 姗姗来迟
        g.observe(2, t + Duration::from_millis(5));
        assert!(
            g.ranges_to_nack(
                t + REORDER_GRACE + Duration::from_millis(1),
                ARQ_DEADLINE_FLOOR
            )
            .is_empty(),
            "已经补上的空洞不该再出现在 NACK 里"
        );
    }

    #[test]
    fn gap_tracker_nacks_genuine_gaps_after_grace_period() {
        let t = Instant::now();
        let mut g = GapTracker::new();
        g.observe(1, t);
        g.observe(5, t); // 2、3、4 缺失
        let ranges = g.ranges_to_nack(
            t + REORDER_GRACE + Duration::from_millis(1),
            ARQ_DEADLINE_FLOOR,
        );
        assert_eq!(ranges, vec![(2, 3)], "连续缺失应该压缩成一个区间");
    }

    #[test]
    fn gap_tracker_gives_up_after_arq_deadline() {
        let t = Instant::now();
        let mut g = GapTracker::new();
        g.observe(1, t);
        g.observe(5, t);
        let too_late = t + ARQ_DEADLINE_FLOOR + Duration::from_millis(1);
        assert!(
            g.ranges_to_nack(too_late, ARQ_DEADLINE_FLOOR).is_empty(),
            "超过 ARQ 截止时间的空洞必须放弃，不能一直 NACK 下去"
        );
    }

    #[test]
    fn gap_tracker_rate_limits_nack_sends() {
        let t = Instant::now();
        let mut g = GapTracker::new();
        g.observe(1, t);
        g.observe(5, t);
        let due = t + REORDER_GRACE + Duration::from_millis(1);
        let first = g.ranges_to_nack(due, ARQ_DEADLINE_FLOOR);
        assert!(!first.is_empty(), "第一次该发");
        let second = g.ranges_to_nack(due + Duration::from_millis(1), ARQ_DEADLINE_FLOOR);
        assert!(second.is_empty(), "限速窗口内不该再发一次");
    }

    /// 这是这版要修的那个真实 bug 的回归测试：高 RTT 链路上，固定 150ms
    /// 的截止时间会让空洞在 NACK 发出去之前就被放弃——实测 RTT 300ms 的
    /// 链路上补包机制因此完全没触发过。改成动态计算之后，同样的空洞在
    /// 高 RTT 下必须还活着。
    #[test]
    fn gap_tracker_survives_high_rtt_with_dynamic_deadline() {
        let t = Instant::now();
        let mut g = GapTracker::new();
        g.observe(1, t);
        g.observe(5, t);
        let rtt = Duration::from_millis(300);
        let deadline = arq_deadline_for(rtt);
        // 固定 150ms 的旧行为：这个时间点空洞早就该被放弃了
        let one_rtt_later = t + rtt;
        assert!(
            !g.ranges_to_nack(one_rtt_later, deadline).is_empty(),
            "按 300ms RTT 动态算出的截止时间，不该在仅过了 1 个 RTT 时就放弃空洞"
        );
    }

    #[test]
    fn arq_deadline_scales_with_rtt_but_stays_within_bounds() {
        assert_eq!(
            arq_deadline_for(Duration::from_millis(1)),
            ARQ_DEADLINE_FLOOR,
            "极低 RTT 不该把截止时间压到比原来验证过的下限还小"
        );
        let high = arq_deadline_for(Duration::from_millis(300));
        assert!(
            high > Duration::from_millis(300),
            "300ms RTT 下算出的截止时间应该明显盖过 1 个 RTT，不能刚好卡线"
        );
        assert_eq!(
            arq_deadline_for(Duration::from_secs(30)),
            ARQ_DEADLINE_CEILING,
            "极端高 RTT 必须封顶，不能无限增长"
        );
    }

    #[test]
    fn send_buffer_hits_are_only_valid_within_the_given_deadline() {
        let t = Instant::now();
        let mut buf = SendBuffer::new();
        buf.push(42, vec![1, 2, 3], None, t);
        assert!(
            buf.get(42, ARQ_DEADLINE_FLOOR).is_some(),
            "刚发的应该能命中"
        );
        // 模拟时间流逝：直接构造一个"很久以前"发送的条目来验证截止时间生效
        buf.entries.get_mut(&42).unwrap().sent_at =
            t - ARQ_DEADLINE_FLOOR - Duration::from_millis(1);
        assert!(
            buf.get(42, ARQ_DEADLINE_FLOOR).is_none(),
            "超过截止时间的条目不该再被命中"
        );
        // 同一个条目，换一个按高 RTT 算出来的更长截止时间，应该又能命中——
        // 这正是这次要修的行为：截止时间必须跟着连接的 RTT 走。
        assert!(
            buf.get(42, arq_deadline_for(Duration::from_millis(300)))
                .is_some(),
            "高 RTT 链路算出的更长截止时间应该能救回同一个条目"
        );
    }

    #[test]
    fn send_buffer_evicts_oldest_entry_when_full() {
        let t = Instant::now();
        let mut buf = SendBuffer::new();
        for i in 0..SEND_BUFFER_CAP as u64 {
            buf.push(i, vec![0], None, t);
        }
        assert!(buf.get(0, ARQ_DEADLINE_FLOOR).is_some());
        buf.push(SEND_BUFFER_CAP as u64, vec![0], None, t);
        assert!(
            buf.get(0, ARQ_DEADLINE_FLOOR).is_none(),
            "满了之后应该淘汰最老的条目"
        );
        assert!(buf
            .get(SEND_BUFFER_CAP as u64, ARQ_DEADLINE_FLOOR)
            .is_some());
    }
}
