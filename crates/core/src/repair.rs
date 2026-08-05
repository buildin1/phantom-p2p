//! 数据面丢包修复
//!
//! # 要解决的问题
//!
//! 数据面走 QUIC DATAGRAM（见 [`crate::tun_bridge`]），**不可靠、不重传**——
//! 这是刻意的选择，避免一个丢包阻塞所有流量。代价是运营商 QoS 丢掉的包彻底没了。
//!
//! 而隧道里跑的大多是 TCP。TCP 严格有序：丢一个包，后面**已经到达**的数据全部卡在
//! 接收缓冲区不能上交应用。玩家看到的就是画面冻住、然后突然跳一下——回弹。
//! 实测 **1% 丢包就已经能感觉到**。
//!
//! # 必须跑赢谁
//!
//! 内层 TCP 自己也会修：有了 RACK-TLP（RFC 8985），它的恢复大约是
//! `检测(~RTT/4) + 重传(1 RTT)`，在 45ms 的链路上约 **55ms**。
//!
//! **所以我们的修复必须显著快于 55ms，否则纯属白做。**
//!
//! # 为什么不能只靠 ARQ（请求重传）
//!
//! 接收端要发现丢包，得等**下一个包**到达才能看出序号有洞。游戏 20~30 包/秒，
//! 包间隔就是 33~50ms。于是：
//!
//! ```text
//! 纯 ARQ:  丢包 → 等下一包暴露空洞(33~50ms) → NACK(22ms) → 补包(22ms) ≈ 80~95ms  ✗ 慢于 55ms
//! 主动冗余: 丢包 → 定时器(15ms) → 副本到达(22ms)                        ≈ 37ms    ✓ 快于 55ms
//! ```
//!
//! 结论：**主力必须是定时器驱动的主动冗余**，ARQ 只做兜底。
//!
//! # 为什么不能无脑全流多发
//!
//! 运营商对高速 UDP 流有风控，触发后**直接掐断连接**。所以冗余强度必须跟着实测丢包率走，
//! 链路干净时零开销，且任何时候都有绝对上限。
//!
//! 参考量级：被掐断的 hy2 代理约 5000 包/秒，而我们 5 人联机约 150 包/秒，
//! 双发后约 300 包/秒——低了一到两个数量级，但仍然不能无节制。
//!
//! # 线格式：数据面**完全不变**
//!
//! 冗余副本与重传都是原报文的**逐字节重发**，计数器相同，由现有的按流重放窗口
//! 自动去重。因此：
//!
//! - 数据报没有任何新增头部，`TUN_MTU` 不用改，不存在满载包超限的风险
//! - 本地 TUN 永远只收到每个 IP 包恰好一份，多倍包只存在于 P2P 双端之间
//!
//! 只新增**控制报文**（NACK / 心跳 / 能力宣告）。传统数据报首字节是 8 字节大端
//! 计数器的最高位，实际恒为 `0x00`（要发满 2^56 个包才非零），因此把控制报文
//! 首字节的 bit7 置 1 即可无歧义区分。旧版本收到控制报文会因"报文过短"丢弃，无害。

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// 控制报文标记位。传统数据报首字节恒为 0，故 bit7 可无歧义区分。
pub const CTRL_MARKER: u8 = 0x80;

pub const CTRL_HELLO: u8 = 0;
pub const CTRL_NACK: u8 = 1;
pub const CTRL_HEARTBEAT: u8 = 2;
const CTRL_TYPE_MASK: u8 = 0x0F;

/// 主动冗余副本相对原包的延后量。
///
/// 不能为 0：紧挨着原包发出的副本，一次持续两个包的突发丢包就能把正副两份一起带走，
/// 冗余等于白加。15ms 既能跨过短突发，又保证总恢复时间（15 + 单程 ~22ms ≈ 37ms）
/// 显著快于内层 TCP 自己的 ~55ms。
pub const FIRST_COPY_DELAY: Duration = Duration::from_millis(15);

/// 多份副本之间的间隔。同样是为了让突发丢不掉全部副本。
pub const COPY_SPACING: Duration = Duration::from_millis(10);

/// 发现空洞后等多久才发 NACK。
///
/// 主动冗余的副本会在 [`FIRST_COPY_DELAY`] 后到达，这个等待窗口让它有机会把洞填上，
/// 避免为一个马上就会被补上的包白发 NACK（那会平白抬高包速率，正撞风控）。
/// 顺带也吸收了正常的网络乱序。
pub const NACK_DELAY: Duration = Duration::from_millis(25);

/// 同一个空洞最多 NACK 几次（每次间隔 [`NACK_DELAY`]）
const MAX_NACK_ATTEMPTS: u32 = 3;

/// 超过这个时间还没补上就放弃：内层 TCP 早已自己重传，再补是纯浪费
pub const REPAIR_DEADLINE: Duration = Duration::from_millis(150);

/// NACK 发送限速。突发丢包会一次性产生大量空洞，
/// 不限速的话瞬间的 NACK 洪水会把包速率顶上去，正撞风控。
pub const NACK_MIN_INTERVAL: Duration = Duration::from_millis(10);

/// 单个 NACK 报文最多携带的区间数，防止报文过大
const MAX_NACK_RANGES: usize = 24;

/// 心跳间隔。捎带"我已发到第几号"，用于发现**尾部丢包**——
/// 接收端靠后续序号暴露空洞，如果丢的正是最后一个包，没有后续序号，
/// 空洞永远不会显形。游戏里这很常见（玩家停下不动）。
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// 能力宣告间隔。持续发送使得后加入/重连的对端也能学到。
pub const HELLO_INTERVAL: Duration = Duration::from_secs(1);

/// 发送缓冲保留时长，需大于 [`REPAIR_DEADLINE`] 才能覆盖所有可能的重传请求
const SEND_BUFFER_TTL: Duration = Duration::from_millis(2000);

/// 发送缓冲的条目数上限，防止极端流量把内存吃光
const SEND_BUFFER_MAX: usize = 4096;

/// 入方向丢包率的统计窗口
pub const LOSS_WINDOW: Duration = Duration::from_secs(2);

/// 反馈（NACK 兼作反馈）之外，单独的丢包率上报间隔
pub const FEEDBACK_INTERVAL: Duration = Duration::from_millis(500);

/// 超过这么久没有对端反馈就回落到保守默认档
pub const FEEDBACK_STALE: Duration = Duration::from_secs(5);

/// 某条流被标记为"最近丢过包"后，冗余保持开启的时长
pub const FLOW_LOSSY_TTL: Duration = Duration::from_secs(3);

/// 最多跟踪多少条"最近丢包"的流，防止内存无界增长
const MAX_LOSSY_FLOWS: usize = 1024;

// ============================================================
// 控制报文
// ============================================================

/// 该数据报是否为控制报文（否则是普通的加密数据报）
pub fn is_control(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|b| b & CTRL_MARKER != 0)
}

fn control_type(datagram: &[u8]) -> Option<u8> {
    datagram.first().map(|b| b & CTRL_TYPE_MASK)
}

/// 能力宣告：告诉对端"我支持丢包修复"
pub fn hello_datagram() -> Vec<u8> {
    vec![CTRL_MARKER | CTRL_HELLO]
}

/// 心跳：捎带本端已发出的最大计数器，用于对端发现尾部丢包
pub fn heartbeat_datagram(highest_sent: u64, observed_loss_bp: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.push(CTRL_MARKER | CTRL_HEARTBEAT);
    out.extend_from_slice(&highest_sent.to_be_bytes());
    out.extend_from_slice(&observed_loss_bp.to_be_bytes());
    out
}

/// 解析心跳，返回 `(对端已发到的最大计数器, 对端观测到的入方向丢包率)`
pub fn parse_heartbeat(datagram: &[u8]) -> Option<(u64, u16)> {
    if datagram.len() < 11 || control_type(datagram) != Some(CTRL_HEARTBEAT) {
        return None;
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(&datagram[1..9]);
    Some((
        u64::from_be_bytes(c),
        u16::from_be_bytes([datagram[9], datagram[10]]),
    ))
}

/// 把缺失的计数器编码成 NACK 报文。
///
/// 用区间编码：突发丢包产生的是连续序号，一段几十个包的突发只占 10 字节。
pub fn encode_nack(missing: &[u64]) -> Option<Vec<u8>> {
    if missing.is_empty() {
        return None;
    }
    // 合并成连续区间
    let mut ranges: Vec<(u64, u16)> = Vec::new();
    let mut start = missing[0];
    let mut len: u32 = 1;
    for &c in &missing[1..] {
        if c == start + len as u64 && len < u16::MAX as u32 {
            len += 1;
        } else {
            ranges.push((start, len as u16));
            start = c;
            len = 1;
        }
        if ranges.len() >= MAX_NACK_RANGES {
            break;
        }
    }
    if ranges.len() < MAX_NACK_RANGES {
        ranges.push((start, len as u16));
    }
    ranges.truncate(MAX_NACK_RANGES);

    let mut out = Vec::with_capacity(2 + ranges.len() * 10);
    out.push(CTRL_MARKER | CTRL_NACK);
    out.push(ranges.len() as u8);
    for (s, l) in ranges {
        out.extend_from_slice(&s.to_be_bytes());
        out.extend_from_slice(&l.to_be_bytes());
    }
    Some(out)
}

/// 解析 NACK，返回被请求重传的计数器列表
pub fn decode_nack(datagram: &[u8]) -> Option<Vec<u64>> {
    if datagram.len() < 2 || control_type(datagram) != Some(CTRL_NACK) {
        return None;
    }
    let count = datagram[1] as usize;
    if datagram.len() < 2 + count * 10 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..count {
        let base = 2 + i * 10;
        let mut c = [0u8; 8];
        c.copy_from_slice(&datagram[base..base + 8]);
        let start = u64::from_be_bytes(c);
        let len = u16::from_be_bytes([datagram[base + 8], datagram[base + 9]]);
        for j in 0..len as u64 {
            out.push(start + j);
            // 防止恶意对端用一个巨大的 len 让我们爆内存
            if out.len() > MAX_NACK_RANGES * u16::MAX as usize / 64 {
                return Some(out);
            }
        }
    }
    Some(out)
}

// ============================================================
// 冗余档位
// ============================================================

/// 冗余档位：每个原包额外发几份副本。
///
/// 稀疏流量下分组攒不满，所以真正起作用的就是"额外发几份"这一个量。
/// 残余丢包 ≈ `p^(copies+1)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairLevel {
    /// 额外副本数（0 表示不主动冗余，只靠 ARQ 兜底）
    pub copies: u8,
    /// 是否对**所有**流开启（false 表示只对最近丢过包的流开启）
    pub all_flows: bool,
}

impl RepairLevel {
    pub const fn new(copies: u8, all_flows: bool) -> Self {
        Self { copies, all_flows }
    }
}

/// 由弱到强的档位阶梯。
///
/// 低档位刻意用"只保护最近丢过包的流"，而不是全流放大——
/// 1% 丢包时绝大多数流是干净的，对它们加冗余纯属浪费包速率预算。
pub const LADDER: [RepairLevel; 5] = [
    RepairLevel::new(0, false), // 干净：只靠 ARQ 兜底
    RepairLevel::new(1, false), // 轻微：仅对丢过包的流双发
    RepairLevel::new(1, true),  // 中度：全流双发
    RepairLevel::new(2, true),  // 重度：全流三发
    RepairLevel::new(3, true),  // 极端：全流四发
];

/// 按平滑后的丢包率选档。
///
/// 低段分得比高段细：**1% 附近就已经有可感知的回弹**，那是最需要分辨率的区间。
pub fn level_for_loss(loss_bp: u16) -> usize {
    match loss_bp {
        0..=49 => 0,      // < 0.5%
        50..=499 => 1,    // 0.5% ~ 5%
        500..=1999 => 2,  // 5% ~ 20%
        2000..=3499 => 3, // 20% ~ 35%
        _ => 4,           // > 35%
    }
}

/// 平滑器的非对称时间常数。
///
/// 上升快、下降慢：**漏保护的代价远大于多花一点包速率**。链路一变差要立刻跟上，
/// 变好之后慢慢收，避免抖动时反复横跳。
const ALPHA_RISE: f64 = 0.5;
const ALPHA_FALL: f64 = 0.05;

/// 丢包率单次跳高超过这个幅度（5 个百分点）就跳过平滑直接跟上。
///
/// 依据：几十个样本下丢包率估计的标准误约 1~2 个百分点，5 个百分点的跳变
/// 远超噪声量级，只可能是链路真的恶化了。
const SNAP_THRESHOLD_BP: f64 = 500.0;

/// 冗余档位控制器
pub struct RepairPolicy {
    level: usize,
    smoothed_loss_bp: f64,
    last_feedback: Option<Instant>,
    /// 档位上限。风控自校准（后续版本）会下压这个值。
    ceiling: usize,
}

impl Default for RepairPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RepairPolicy {
    pub fn new() -> Self {
        Self {
            level: 0,
            smoothed_loss_bp: 0.0,
            last_feedback: None,
            ceiling: LADDER.len() - 1,
        }
    }

    pub fn level(&self) -> RepairLevel {
        LADDER[self.level.min(LADDER.len() - 1)]
    }

    pub fn level_index(&self) -> usize {
        self.level
    }

    pub fn smoothed_loss_bp(&self) -> u16 {
        self.smoothed_loss_bp.round().clamp(0.0, 10_000.0) as u16
    }

    /// 设定档位上限（风控自校准用）
    pub fn set_ceiling(&mut self, ceiling: usize) {
        self.ceiling = ceiling.min(LADDER.len() - 1);
        self.level = self.level.min(self.ceiling);
    }

    /// 喂入对端报告的入方向丢包率
    pub fn observe(&mut self, loss_bp: u16, now: Instant) {
        self.last_feedback = Some(now);
        let raw = loss_bp as f64;
        if raw > self.smoothed_loss_bp + SNAP_THRESHOLD_BP {
            // 大幅恶化直接跟上，不做平滑。
            // 平滑的目的是滤掉抽样噪声（几十个样本下丢包率估计的标准误有一两个百分点），
            // 而"突然跳高 5 个百分点以上"远超噪声量级，只可能是链路真的坏了——
            // 这时候还慢慢爬，玩家会实实在在卡上一两秒。
            self.smoothed_loss_bp = raw;
        } else {
            let alpha = if raw > self.smoothed_loss_bp {
                ALPHA_RISE
            } else {
                ALPHA_FALL
            };
            self.smoothed_loss_bp += alpha * (raw - self.smoothed_loss_bp);
        }
        self.level = level_for_loss(self.smoothed_loss_bp()).min(self.ceiling);
    }

    /// 反馈中断太久就回落（对端可能换了链路或掉线重连）
    pub fn tick(&mut self, now: Instant) {
        if let Some(last) = self.last_feedback {
            if now.duration_since(last) > FEEDBACK_STALE {
                self.smoothed_loss_bp = 0.0;
                self.level = 0;
                self.last_feedback = None;
            }
        }
    }
}

// ============================================================
// 发送端
// ============================================================

/// 已发出报文的留存缓冲，供重传与冗余副本使用。
///
/// 同时记录该报文属于哪条内层流：接收端**无法**告诉我们"哪条流丢了包"
/// （它连那个包都没收到，自然看不到五元组），但 NACK 会告诉我们**哪些计数器**丢了，
/// 而发送端这里有计数器到流的映射——于是就能反推出哪条流在丢包，
/// 从而只对这些流开启冗余，而不是全流放大。
pub struct SendBuffer {
    entries: BTreeMap<u64, Entry>,
    order: VecDeque<u64>,
}

struct Entry {
    sent_at: Instant,
    flow: u64,
    payload: std::sync::Arc<[u8]>,
}

impl Default for SendBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SendBuffer {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn push(&mut self, counter: u64, flow: u64, payload: std::sync::Arc<[u8]>, now: Instant) {
        self.entries.insert(
            counter,
            Entry {
                sent_at: now,
                flow,
                payload,
            },
        );
        self.order.push_back(counter);
        while self.order.len() > SEND_BUFFER_MAX {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }

    /// 取出可重传的报文；顺带返回它属于哪条流
    pub fn get(&self, counter: u64) -> Option<(u64, std::sync::Arc<[u8]>)> {
        self.entries
            .get(&counter)
            .map(|e| (e.flow, e.payload.clone()))
    }

    pub fn expire(&mut self, now: Instant) {
        while let Some(&front) = self.order.front() {
            let too_old = self
                .entries
                .get(&front)
                .is_none_or(|e| now.duration_since(e.sent_at) > SEND_BUFFER_TTL);
            if !too_old {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&front);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 记录哪些内层流最近丢过包，用于把冗余**只**施加在这些流上。
pub struct LossyFlows {
    flows: HashMap<u64, Instant>,
}

impl Default for LossyFlows {
    fn default() -> Self {
        Self::new()
    }
}

impl LossyFlows {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn mark(&mut self, flow: u64, now: Instant) {
        if self.flows.len() >= MAX_LOSSY_FLOWS {
            // 满了先清一遍过期的，还满就放弃这次标记（宁可少保护也不能吃光内存）
            self.expire(now);
            if self.flows.len() >= MAX_LOSSY_FLOWS {
                return;
            }
        }
        self.flows.insert(flow, now);
    }

    pub fn is_lossy(&self, flow: u64, now: Instant) -> bool {
        self.flows
            .get(&flow)
            .is_some_and(|t| now.duration_since(*t) <= FLOW_LOSSY_TTL)
    }

    pub fn expire(&mut self, now: Instant) {
        self.flows
            .retain(|_, t| now.duration_since(*t) <= FLOW_LOSSY_TTL);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}

/// 排程待发的冗余副本/重传（按到期时间递增）
pub struct SendQueue {
    items: VecDeque<(Instant, std::sync::Arc<[u8]>)>,
}

impl Default for SendQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl SendQueue {
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }

    pub fn schedule(&mut self, due: Instant, payload: std::sync::Arc<[u8]>) {
        // 保持按到期时间有序，否则 take_due 会漏发
        let pos = self
            .items
            .iter()
            .position(|(t, _)| *t > due)
            .unwrap_or(self.items.len());
        self.items.insert(pos, (due, payload));
    }

    pub fn take_due(&mut self, now: Instant) -> Vec<std::sync::Arc<[u8]>> {
        let mut out = Vec::new();
        while let Some((due, _)) = self.items.front() {
            if *due > now {
                break;
            }
            let (_, payload) = self.items.pop_front().expect("刚判断过非空");
            out.push(payload);
        }
        out
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

// ============================================================
// 接收端：丢包检测
// ============================================================

struct Hole {
    first_missed: Instant,
    nacked: u32,
    last_nack: Option<Instant>,
}

/// 基于 overlay 计数器空洞的**入方向**丢包检测。
///
/// # 为什么不用 QUIC 的路径统计
///
/// `quinn` 的 `path.lost_packets` 测的是"**我发出去**的包丢了多少"（出方向），
/// 而毁掉体验的是"对端发给我、我没收到"的包（入方向）——那个数据只存在于
/// **对端**的 QUIC 栈里，本地怎么读都读不到。
///
/// overlay 计数器则天然是端到端、入方向的，中继模式下也照样准。
pub struct LossDetector {
    highest: u64,
    holes: BTreeMap<u64, Hole>,
    started: bool,
    /// 本窗口内收到的包数
    window_received: u64,
    /// 本窗口起始计数器
    window_start: u64,
    window_began: Instant,
    /// 本窗口内确认丢失（放弃修复）的包数
    window_lost: u64,
    /// 累计成功修复的包数（遥测）
    pub repaired_total: u64,
    last_nack_sent: Option<Instant>,
}

impl LossDetector {
    pub fn new(now: Instant) -> Self {
        Self {
            highest: 0,
            holes: BTreeMap::new(),
            started: false,
            window_received: 0,
            window_start: 0,
            window_began: now,
            window_lost: 0,
            repaired_total: 0,
            last_nack_sent: None,
        }
    }

    /// 记录一个成功交付的报文。返回 true 表示它填上了一个已知空洞（即修复成功）。
    pub fn on_received(&mut self, counter: u64, now: Instant) -> bool {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.window_start = counter;
            self.window_received = 1;
            return false;
        }

        let filled = self.holes.remove(&counter).is_some();
        if filled {
            self.repaired_total += 1;
        }

        // 只有**首次见到**的序号才计入收包数。
        //
        // 这一步不能省：冗余副本和重传带的是同一个计数器，也会走到这里。
        // 若把它们一并计入，丢包就会被副本"掩盖"——比如窗口跨度 100、真丢 5 个、
        // 另有 20 个副本，收包数会算成 115（截断成 100），丢包率报 0%，
        // 于是档位永远升不上去，整个自适应闭环失效。
        let is_new = counter > self.highest || filled;

        if counter > self.highest {
            // 中间跳过的序号就是新的空洞
            for missing in (self.highest + 1)..counter {
                self.holes.insert(
                    missing,
                    Hole {
                        first_missed: now,
                        nacked: 0,
                        last_nack: None,
                    },
                );
            }
            self.highest = counter;
        }
        if is_new {
            self.window_received += 1;
        }
        filled
    }

    /// 对端心跳告知它已发到 `peer_highest`，据此发现**尾部**丢包
    pub fn observe_peer_highest(&mut self, peer_highest: u64, now: Instant) {
        if !self.started || peer_highest <= self.highest {
            return;
        }
        for missing in (self.highest + 1)..=peer_highest {
            self.holes.entry(missing).or_insert(Hole {
                first_missed: now,
                nacked: 0,
                last_nack: None,
            });
        }
        self.highest = peer_highest;
    }

    /// 挑出该发 NACK 的空洞；同时清理已超时放弃的。
    ///
    /// 返回 `None` 表示这次不该发（没有到期的空洞，或距上次 NACK 太近）。
    pub fn poll_nack(&mut self, now: Instant) -> Option<Vec<u64>> {
        // 先清理超过修复截止时间的：内层 TCP 早已自己重传，再补是浪费
        let expired: Vec<u64> = self
            .holes
            .iter()
            .filter(|(_, h)| {
                now.duration_since(h.first_missed) > REPAIR_DEADLINE
                    || h.nacked >= MAX_NACK_ATTEMPTS
            })
            .map(|(c, _)| *c)
            .collect();
        for c in expired {
            self.holes.remove(&c);
            self.window_lost += 1;
        }

        // 限速：突发丢包会一次产生大量空洞，不限速会造成 NACK 洪水
        if let Some(last) = self.last_nack_sent {
            if now.duration_since(last) < NACK_MIN_INTERVAL {
                return None;
            }
        }

        let due: Vec<u64> = self
            .holes
            .iter()
            .filter(|(_, h)| {
                let waited = match h.last_nack {
                    // 首次：等一个窗口，给主动冗余的副本填洞的机会
                    None => now.duration_since(h.first_missed) >= NACK_DELAY,
                    // 重发：上次 NACK 之后又等了一个窗口仍没补上
                    Some(t) => now.duration_since(t) >= NACK_DELAY,
                };
                waited
            })
            .map(|(c, _)| *c)
            .take(MAX_NACK_RANGES * 64)
            .collect();

        if due.is_empty() {
            return None;
        }
        for c in &due {
            if let Some(h) = self.holes.get_mut(c) {
                h.nacked += 1;
                h.last_nack = Some(now);
            }
        }
        self.last_nack_sent = Some(now);
        Some(due)
    }

    /// 窗口是否该结算
    pub fn window_due(&self, now: Instant) -> bool {
        self.started && now.duration_since(self.window_began) >= LOSS_WINDOW
    }

    /// 结算窗口，返回**原始**入方向丢包率（万分之一）。
    ///
    /// 用原始丢包（含被修复回来的）而不是残余丢包来驱动冗余档位：
    /// 残余低只是说明当前冗余够用，一旦据此降档，丢包会立刻卷土重来。
    pub fn settle(&mut self, now: Instant) -> u16 {
        let span = self.highest.saturating_sub(self.window_start) + 1;
        let received = self.window_received.min(span);
        let missing = span - received;
        let bp = if span == 0 {
            0
        } else {
            ((missing.saturating_mul(10_000)) / span).min(10_000) as u16
        };
        self.window_start = self.highest + 1;
        self.window_received = 0;
        self.window_lost = 0;
        self.window_began = now;
        bp
    }

    pub fn pending_holes(&self) -> usize {
        self.holes.len()
    }
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    /// 传统数据报首字节恒为 0，绝不能被误判成控制报文——
    /// 这是新旧版本互通的地基，破坏它所有旧客户端都会断
    #[test]
    fn legacy_datagrams_are_never_mistaken_for_control() {
        for counter in [0u64, 1, 1000, u32::MAX as u64, 1 << 55] {
            let mut d = counter.to_be_bytes().to_vec();
            d.extend_from_slice(b"ciphertext");
            assert!(!is_control(&d), "counter={} 被误判为控制报文", counter);
        }
    }

    #[test]
    fn control_datagrams_are_recognised() {
        assert!(is_control(&hello_datagram()));
        assert!(is_control(&heartbeat_datagram(42, 100)));
        assert!(is_control(&encode_nack(&[1, 2, 3]).unwrap()));
    }

    #[test]
    fn heartbeat_roundtrips() {
        let d = heartbeat_datagram(123_456_789, 250);
        assert_eq!(parse_heartbeat(&d), Some((123_456_789, 250)));
        // 类型不对的不该被解析成心跳
        assert_eq!(parse_heartbeat(&hello_datagram()), None);
    }

    #[test]
    fn nack_roundtrips_single_values() {
        let missing = vec![10u64, 20, 30];
        let encoded = encode_nack(&missing).unwrap();
        assert_eq!(decode_nack(&encoded).unwrap(), missing);
    }

    /// 突发丢包产生的是连续序号，必须被压成区间，否则 NACK 报文会爆炸
    #[test]
    fn nack_compresses_consecutive_runs() {
        let missing: Vec<u64> = (100..160).collect();
        let encoded = encode_nack(&missing).unwrap();
        assert!(
            encoded.len() < 20,
            "60 个连续序号应压成一个区间，实得 {} 字节",
            encoded.len()
        );
        assert_eq!(decode_nack(&encoded).unwrap(), missing);
    }

    #[test]
    fn empty_nack_is_not_encoded() {
        assert!(encode_nack(&[]).is_none());
    }

    #[test]
    fn malformed_control_is_rejected() {
        assert!(decode_nack(&[]).is_none());
        assert!(decode_nack(&[CTRL_MARKER | CTRL_NACK]).is_none());
        // 声明 5 个区间但数据不够
        assert!(decode_nack(&[CTRL_MARKER | CTRL_NACK, 5, 0, 0]).is_none());
        assert!(parse_heartbeat(&[CTRL_MARKER | CTRL_HEARTBEAT, 1, 2]).is_none());
    }

    // ---------- 丢包检测 ----------

    #[test]
    fn clean_stream_reports_no_loss() {
        let t = t0();
        let mut d = LossDetector::new(t);
        for c in 0..100u64 {
            d.on_received(c, t);
        }
        assert_eq!(d.pending_holes(), 0);
        assert_eq!(d.settle(t + LOSS_WINDOW), 0);
    }

    #[test]
    fn gap_becomes_a_hole() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(2, t);
        d.on_received(5, t); // 3、4 丢了
        assert_eq!(d.pending_holes(), 2);
    }

    /// 空洞被后到的包填上，必须算作修复成功而不是继续 NACK
    #[test]
    fn late_arrival_fills_hole_and_counts_as_repair() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(3, t);
        assert_eq!(d.pending_holes(), 1);
        assert!(d.on_received(2, t), "填补空洞应返回 true");
        assert_eq!(d.pending_holes(), 0);
        assert_eq!(d.repaired_total, 1);
    }

    /// NACK 不能一发现空洞就发：主动冗余的副本马上就到，
    /// 立刻 NACK 会为一个即将被补上的包白发请求，平白抬高包速率
    #[test]
    fn nack_waits_for_the_redundancy_window() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(3, t);
        assert!(d.poll_nack(t).is_none(), "刚发现空洞不该立刻 NACK");
        assert!(
            d.poll_nack(t + NACK_DELAY).is_some(),
            "等过冗余窗口后才该发 NACK"
        );
    }

    #[test]
    fn nack_is_rate_limited() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(10, t);
        let at = t + NACK_DELAY;
        assert!(d.poll_nack(at).is_some());
        assert!(
            d.poll_nack(at + Duration::from_millis(1)).is_none(),
            "限速期内不得再发 NACK，否则突发丢包会造成 NACK 洪水"
        );
    }

    /// 超过修复截止时间就该放弃：内层 TCP 早已自己重传，再补是纯浪费
    #[test]
    fn holes_are_abandoned_after_deadline() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(3, t);
        assert_eq!(d.pending_holes(), 1);
        d.poll_nack(t + REPAIR_DEADLINE + Duration::from_millis(1));
        assert_eq!(d.pending_holes(), 0, "超时的空洞必须被放弃");
    }

    #[test]
    fn holes_give_up_after_max_attempts() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(3, t);
        let mut at = t;
        for _ in 0..MAX_NACK_ATTEMPTS {
            at += NACK_DELAY;
            d.poll_nack(at);
        }
        at += NACK_DELAY;
        d.poll_nack(at);
        assert_eq!(d.pending_holes(), 0, "重试到上限后应放弃");
    }

    /// 尾包丢失时没有后续序号能暴露空洞，必须靠心跳发现——
    /// 游戏里玩家停下不动就是这个场景
    #[test]
    fn heartbeat_detects_tail_loss() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(1, t);
        d.on_received(2, t);
        assert_eq!(d.pending_holes(), 0, "此时还看不出尾部丢了");
        d.observe_peer_highest(5, t);
        assert_eq!(d.pending_holes(), 3, "心跳应暴露 3、4、5 的缺失");
    }

    #[test]
    fn heartbeat_does_not_invent_holes_when_up_to_date() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(7, t);
        d.observe_peer_highest(7, t);
        assert_eq!(d.pending_holes(), 0);
        d.observe_peer_highest(3, t); // 落后的心跳，忽略
        assert_eq!(d.pending_holes(), 0);
    }

    /// 冗余副本带的是同一个计数器，绝不能把它算成"又收到一个包"——
    /// 否则丢包会被副本掩盖，丢包率报 0，档位永远升不上去，自适应彻底失效
    #[test]
    fn duplicate_copies_do_not_mask_loss() {
        let t = t0();
        let mut d = LossDetector::new(t);
        // 0..100 收到 95 个（5、15、25、35、45 丢了）
        for c in 0..100u64 {
            if c % 10 == 5 && c < 50 {
                continue;
            }
            d.on_received(c, t);
        }
        // 每个包又各来了一份冗余副本
        for c in 0..100u64 {
            if c % 10 == 5 && c < 50 {
                continue;
            }
            d.on_received(c, t);
        }
        let bp = d.settle(t + LOSS_WINDOW);
        assert!(
            (400..=600).contains(&bp),
            "5/100 丢包应报 ~5%，副本不该掩盖它，实得 {}bp",
            bp
        );
    }

    /// 但被补回来的包要算数——它确实交付了，只是绕了一圈
    #[test]
    fn repaired_packet_counts_as_received() {
        let t = t0();
        let mut d = LossDetector::new(t);
        d.on_received(0, t);
        d.on_received(2, t); // 1 丢了
        d.on_received(1, t); // 补回来了
        for c in 3..100u64 {
            d.on_received(c, t);
        }
        assert_eq!(d.settle(t + LOSS_WINDOW), 0, "全部补齐后不该再报丢包");
    }

    #[test]
    fn loss_rate_is_measured_over_window() {
        let t = t0();
        let mut d = LossDetector::new(t);
        // 0..100 里只收到偶数 → 丢一半
        for c in (0..100u64).step_by(2) {
            d.on_received(c, t);
        }
        let bp = d.settle(t + LOSS_WINDOW);
        assert!(
            (4800..=5100).contains(&bp),
            "丢一半应报 ~50%，实得 {}bp",
            bp
        );
    }

    // ---------- 发送缓冲 ----------

    #[test]
    fn send_buffer_returns_payload_and_flow() {
        let t = t0();
        let mut b = SendBuffer::new();
        b.push(7, 42, std::sync::Arc::from(&b"hello"[..]), t);
        let (flow, payload) = b.get(7).unwrap();
        assert_eq!(flow, 42);
        assert_eq!(&*payload, b"hello");
        assert!(b.get(8).is_none());
    }

    #[test]
    fn send_buffer_expires_old_entries() {
        let t = t0();
        let mut b = SendBuffer::new();
        b.push(1, 0, std::sync::Arc::from(&b"x"[..]), t);
        b.expire(t + SEND_BUFFER_TTL + Duration::from_millis(1));
        assert!(b.is_empty(), "过期条目必须回收");
    }

    #[test]
    fn send_buffer_is_bounded() {
        let t = t0();
        let mut b = SendBuffer::new();
        for c in 0..(SEND_BUFFER_MAX as u64 * 2) {
            b.push(c, 0, std::sync::Arc::from(&b"x"[..]), t);
        }
        assert!(
            b.len() <= SEND_BUFFER_MAX,
            "缓冲必须有上限，否则大流量会吃光内存"
        );
    }

    // ---------- 丢包流记忆 ----------

    #[test]
    fn lossy_flow_is_remembered_then_forgotten() {
        let t = t0();
        let mut f = LossyFlows::new();
        f.mark(1, t);
        assert!(f.is_lossy(1, t));
        assert!(!f.is_lossy(2, t), "没丢过包的流不该被保护");
        assert!(
            !f.is_lossy(1, t + FLOW_LOSSY_TTL + Duration::from_millis(1)),
            "安静下来的流应自动退出保护，否则冗余永远撤不掉"
        );
    }

    #[test]
    fn lossy_flows_are_bounded() {
        let t = t0();
        let mut f = LossyFlows::new();
        for i in 0..(MAX_LOSSY_FLOWS as u64 * 2) {
            f.mark(i, t);
        }
        assert!(f.len() <= MAX_LOSSY_FLOWS);
    }

    // ---------- 排程队列 ----------

    #[test]
    fn queue_releases_items_in_time_order() {
        let t = t0();
        let mut q = SendQueue::new();
        q.schedule(
            t + Duration::from_millis(30),
            std::sync::Arc::from(&b"c"[..]),
        );
        q.schedule(
            t + Duration::from_millis(10),
            std::sync::Arc::from(&b"a"[..]),
        );
        q.schedule(
            t + Duration::from_millis(20),
            std::sync::Arc::from(&b"b"[..]),
        );

        assert!(q.take_due(t).is_empty(), "还没到期不该发");
        let due = q.take_due(t + Duration::from_millis(20));
        assert_eq!(due.len(), 2, "到期的都要发出去");
        assert_eq!(&*due[0], b"a", "必须按到期时间排序，否则会漏发");
        assert_eq!(&*due[1], b"b");
    }

    // ---------- 档位策略 ----------

    #[test]
    fn ladder_is_monotonically_stronger() {
        for w in LADDER.windows(2) {
            let a = w[0].copies as u32 * 2 + w[0].all_flows as u32;
            let b = w[1].copies as u32 * 2 + w[1].all_flows as u32;
            assert!(b > a, "档位必须单调增强");
        }
    }

    /// 干净链路必须零冗余——这是包速率预算的地基
    #[test]
    fn clean_link_costs_nothing() {
        assert_eq!(LADDER[level_for_loss(0)].copies, 0);
        assert_eq!(LADDER[level_for_loss(10)].copies, 0);
    }

    /// 1% 丢包就已经能感觉到回弹，必须已经在保护状态
    #[test]
    fn one_percent_loss_enables_protection() {
        let level = LADDER[level_for_loss(100)];
        assert_eq!(level.copies, 1, "1% 丢包应开启冗余");
        assert!(
            !level.all_flows,
            "但只该保护丢过包的流，全流放大会触发运营商风控"
        );
    }

    #[test]
    fn heavy_loss_protects_all_flows() {
        assert!(LADDER[level_for_loss(1000)].all_flows);
        assert!(LADDER[level_for_loss(5000)].copies >= 3);
    }

    /// 升档要快：丢包已经在伤害体验，不能慢慢来。
    /// 平滑器一旦把首次观测 damp 掉一半，就要 2~3 个窗口（1~1.5 秒）才升到位，
    /// 那段时间玩家是实实在在卡着的。
    #[test]
    fn policy_escalates_immediately() {
        let t = t0();
        let mut p = RepairPolicy::new();
        p.observe(3000, t);
        assert!(
            p.level_index() >= 3,
            "高丢包应一次观测就升到高档，实得档位 {}",
            p.level_index()
        );
    }

    /// 但小幅波动必须继续走平滑，否则调的是噪声不是丢包
    #[test]
    fn policy_smooths_small_fluctuations() {
        let t = t0();
        let mut p = RepairPolicy::new();
        p.observe(100, t); // 1%
        let after_first = p.smoothed_loss_bp();
        p.observe(300, t); // 抖到 3%，仍在噪声量级内
        assert!(
            p.smoothed_loss_bp() < 300,
            "小幅上升应被平滑（{} → {}），不能直接跟上噪声",
            after_first,
            p.smoothed_loss_bp()
        );
    }

    /// 降档要慢：抖动时反复横跳会让接收端反复经历"冗余不足"
    #[test]
    fn policy_decays_slowly() {
        let t = t0();
        let mut p = RepairPolicy::new();
        p.observe(3000, t);
        let high = p.level_index();
        p.observe(0, t);
        assert_eq!(p.level_index(), high, "一次干净观测不该立刻降档");
        for _ in 0..100 {
            p.observe(0, t);
        }
        assert_eq!(p.level_index(), 0, "持续干净后应回到零冗余");
    }

    #[test]
    fn policy_falls_back_when_feedback_stops() {
        let t = t0();
        let mut p = RepairPolicy::new();
        p.observe(3000, t);
        assert!(p.level_index() > 0);
        p.tick(t + FEEDBACK_STALE + Duration::from_secs(1));
        assert_eq!(p.level_index(), 0, "反馈中断应回落，不能一直高冗余空转");
    }

    #[test]
    fn ceiling_caps_the_level() {
        let t = t0();
        let mut p = RepairPolicy::new();
        p.set_ceiling(1);
        p.observe(9000, t);
        assert_eq!(p.level_index(), 1, "风控上限必须压得住自适应");
    }
}
