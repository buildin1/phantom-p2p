//! 数据面前向纠错（FEC）
//!
//! # 为什么需要这一层
//!
//! 数据面走 QUIC DATAGRAM（见 [`crate::tun_bridge`]），**不可靠、不重传**——
//! 这是刻意的选择，避免一个丢包阻塞所有流量。代价是丢了就是真丢了。
//!
//! 而内层跑的大多是 TCP（我的世界 Java 版就是）。隧道丢一个包，内层 TCP 的恢复路径是：
//! 快速重传需要凑够 3 个重复 ACK——游戏是小包间歇发送，经常凑不够；于是退化到
//! RTO 超时重传，几百毫秒起步。更糟的是 TCP 严格有序交付，丢一个包会把后面**已经到达**
//! 的数据全卡在接收缓冲区。这就是跨省 QoS 链路上"回弹"的直接来源。
//!
//! 只要 FEC 能赶在内层 TCP 的 RTO 之前把包纠出来，内层 TCP **根本感知不到丢过包**，
//! 整段慢速恢复路径直接免掉。所以对 TCP 的收益比对 UDP 还大。
//!
//! # 分层位置：包在加密层**外面**
//!
//! ```text
//! IP 包 ──seal()──> [counter][ct+tag] ──FEC──> [FEC 头][sealed]   数据报
//!                                              [FEC 头][parity]   校验报
//! ```
//!
//! 校验分片是**密文**的线性组合。攻击者伪造 parity 会导致恢复出垃圾分片，
//! 但垃圾分片喂给 `open()` 时 AEAD 认证必然失败被丢弃——**伪造 parity 无法注入流量**，
//! 最坏只是浪费 CPU，而能干这事的在途攻击者本来就能直接丢包。
//! FEC 头虽是明文，同理不构成新攻击面。
//!
//! # 零延迟惩罚
//!
//! 数据包 `seal()` 完**立即发出**，绝不为了攒够一组而缓冲。只有"本来会彻底丢失"
//! 的包才需要等恢复。这条必须守死。
//!
//! # 能力协商：带内探测，不动信令
//!
//! 传统格式的数据报首字节是 8 字节大端计数器的最高位，实际永远是 `0x00`
//! （要发满 2^56 个包才会非零）。因此把 FEC 头首字节的 bit7 恒置 1，
//! 就能无歧义地区分两种格式：
//!
//! - `datagram[0] & 0x80 == 0` → 传统格式（直接是 sealed）
//! - `datagram[0] & 0x80 != 0` → FEC 格式
//!
//! 双方都能同时**接收**两种格式；**发送**哪种取决于是否收到过对端的 HELLO。
//! 旧版本永远不发 HELLO，新版本就一直用传统格式跟它通信。
//!
//! 这样做的关键好处是**失败安全**：任何一环出问题都只会退回当前行为，
//! 而不会把 FEC 格式发给一个看不懂它的对端导致隧道整体不通。

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// FEC 格式标记位。传统格式首字节恒为 0，故 bit7 可无歧义区分两种格式。
pub const FEC_MARKER: u8 = 0x80;

pub const TYPE_DATA: u8 = 0;
pub const TYPE_PARITY: u8 = 1;
pub const TYPE_CONTROL: u8 = 2;
pub const TYPE_HELLO: u8 = 3;
const TYPE_MASK: u8 = 0x03;

/// DATA 头：flags(1) + group_id(3) + index(1)
pub const DATA_HEADER_LEN: usize = 5;
/// PARITY 头：DATA 头 + k(1) + r(1) + shard_size(2)
pub const PARITY_HEADER_LEN: usize = 9;
/// CONTROL 报文总长：flags(1) + 4 个 u16 字段
pub const CONTROL_LEN: usize = 9;

/// 分组内数据分片前置的长度前缀字节数。
///
/// RS 要求所有分片等长，但 IP 包长度差异极大（40 ~ 1160）。
/// 做法是**只在计算 parity 时**把每个 sealed 补齐到 `shard_size`，
/// 前置 2 字节真实长度以便恢复后还原；**实际发送的数据包保持原始长度**。
/// 只有 parity 是满长度的，正常路径零浪费。
const LEN_PREFIX: usize = 2;

/// 分组最长开启时间。稀疏流量靠它关组，此时组会退化成"冗余双发"——
/// 稀疏本身意味着流量极小，绝对带宽可忽略。
pub const GROUP_FLUSH_INTERVAL: Duration = Duration::from_millis(15);

/// 分组恢复截止时间。超时未凑齐直接丢弃：再晚恢复出来内层 TCP 早已 RTO，
/// 救回来没有意义，白占内存。
const GROUP_DEADLINE: Duration = Duration::from_millis(200);

/// 每个对端最多保留的未完成分组数，防止对端伪造海量 group_id 耗尽内存。
const MAX_OPEN_GROUPS: usize = 64;

/// 入方向丢包率的统计窗口长度
pub const LOSS_WINDOW: Duration = Duration::from_secs(2);

/// HELLO 报文发送间隔。1 字节/秒，可忽略；持续发送使得后加入的对端也能学到。
pub const HELLO_INTERVAL: Duration = Duration::from_secs(1);

/// 反馈报文发送间隔
pub const FEEDBACK_INTERVAL: Duration = Duration::from_millis(500);

/// 超过这个时间没收到对端反馈就回落到安全默认档
pub const FEEDBACK_STALE: Duration = Duration::from_secs(5);

fn flags_of(datagram: &[u8]) -> Option<u8> {
    datagram.first().copied()
}

/// 该数据报是否为 FEC 格式（否则是传统的裸 sealed 报文）
pub fn is_fec(datagram: &[u8]) -> bool {
    flags_of(datagram).is_some_and(|f| f & FEC_MARKER != 0)
}

fn packet_type(flags: u8) -> u8 {
    flags & TYPE_MASK
}

/// 单字节 HELLO 报文：向对端宣告"我支持 FEC 格式"
pub fn hello_datagram() -> Vec<u8> {
    vec![FEC_MARKER | TYPE_HELLO]
}

// ============================================================
// 反馈报文
// ============================================================

/// 接收端回传给发送端的链路观测。
///
/// 丢包率用**万分之一**表示（0..=10000），u16 足够且省字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeedbackReport {
    /// FEC 恢复**之前**的原始入方向丢包率 —— 用来决定冗余率
    pub raw_loss_bp: u16,
    /// FEC 恢复**之后**仍然缺失的比例 —— 用来验证冗余够不够
    pub residual_loss_bp: u16,
    /// 本窗口内成功恢复的包数
    pub recovered: u16,
    /// 统计窗口长度（毫秒）
    pub window_ms: u16,
}

impl FeedbackReport {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTROL_LEN);
        out.push(FEC_MARKER | TYPE_CONTROL);
        out.extend_from_slice(&self.raw_loss_bp.to_be_bytes());
        out.extend_from_slice(&self.residual_loss_bp.to_be_bytes());
        out.extend_from_slice(&self.recovered.to_be_bytes());
        out.extend_from_slice(&self.window_ms.to_be_bytes());
        out
    }

    pub fn decode(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < CONTROL_LEN {
            return None;
        }
        let g = |i: usize| u16::from_be_bytes([datagram[i], datagram[i + 1]]);
        Some(Self {
            raw_loss_bp: g(1),
            residual_loss_bp: g(3),
            recovered: g(5),
            window_ms: g(7),
        })
    }
}

// ============================================================
// 冗余档位
// ============================================================

/// 一个冗余档位：k 个数据分片 + r 个校验分片
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redundancy {
    pub k: usize,
    pub r: usize,
}

impl Redundancy {
    pub const fn new(k: usize, r: usize) -> Self {
        Self { k, r }
    }
    /// 带宽溢价（百分比）
    pub fn overhead_pct(&self) -> u32 {
        (self.r * 100 / self.k.max(1)) as u32
    }
}

/// 由弱到强的档位阶梯。自适应只在这个阶梯上移动。
pub const LADDER: [Redundancy; 4] = [
    Redundancy::new(8, 1), // 12.5%
    Redundancy::new(8, 2), // 25%
    Redundancy::new(4, 2), // 50%
    Redundancy::new(2, 2), // 100%，≈ 双发
];

/// 没有任何反馈时的默认档位。取中档：宁可多花一点带宽，
/// 也不要在还没测出丢包率的头几秒把体验做砸。
pub const DEFAULT_LEVEL: usize = 2;

/// 按观测到的原始丢包率选择档位下标。
pub fn level_for_loss(raw_loss_bp: u16) -> usize {
    match raw_loss_bp {
        0..=49 => 0,     // < 0.5%
        50..=199 => 1,   // 0.5% ~ 2%
        200..=599 => 2,  // 2% ~ 6%
        _ => 3,          // > 6%
    }
}

/// 冗余档位控制器：升档快、降档慢。
///
/// 链路抖动时如果升降同样灵敏，会在两个档位间来回震荡，
/// 反而让接收端反复经历"冗余不足"的窗口。所以降档要连续多次观测确认。
pub struct RedundancyController {
    level: usize,
    /// 连续观测到"可以降档"的次数
    downgrade_streak: u32,
    /// 手动档位下限（UI 设置），自适应只能在其之上加码
    floor: usize,
    last_feedback: Option<Instant>,
}

/// 需要连续这么多次反馈都指向低档，才真的降档（每次 500ms，约 5 秒）
const DOWNGRADE_CONFIRMATIONS: u32 = 10;

impl RedundancyController {
    pub fn new(floor: usize) -> Self {
        Self {
            level: DEFAULT_LEVEL.max(floor),
            downgrade_streak: 0,
            floor,
            last_feedback: None,
        }
    }

    pub fn current(&self) -> Redundancy {
        LADDER[self.level.min(LADDER.len() - 1)]
    }

    pub fn level(&self) -> usize {
        self.level
    }

    /// 收到对端反馈后更新档位
    pub fn observe(&mut self, report: FeedbackReport, now: Instant) {
        self.last_feedback = Some(now);
        let want = level_for_loss(report.raw_loss_bp).max(self.floor);
        if want > self.level {
            // 升档立即生效——丢包已经在伤害体验了，不能等
            self.level = want;
            self.downgrade_streak = 0;
        } else if want < self.level {
            self.downgrade_streak += 1;
            if self.downgrade_streak >= DOWNGRADE_CONFIRMATIONS {
                self.level -= 1;
                self.downgrade_streak = 0;
            }
        } else {
            self.downgrade_streak = 0;
        }
    }

    /// 反馈中断太久就回落到安全默认档（对端可能换了链路或掉线重连）
    pub fn tick(&mut self, now: Instant) {
        if let Some(last) = self.last_feedback {
            if now.duration_since(last) > FEEDBACK_STALE {
                self.level = DEFAULT_LEVEL.max(self.floor);
                self.downgrade_streak = 0;
                self.last_feedback = None;
            }
        }
    }
}

// ============================================================
// RS 编解码器缓存
// ============================================================

/// `ReedSolomon::new` 要构造生成矩阵，每组新建一次太浪费，按 (k,r) 缓存。
#[derive(Default)]
struct CodecCache {
    codecs: HashMap<(usize, usize), ReedSolomon>,
}

impl CodecCache {
    fn get(&mut self, k: usize, r: usize) -> Option<&ReedSolomon> {
        if k == 0 || r == 0 || k + r > 255 {
            return None;
        }
        Some(
            self.codecs
                .entry((k, r))
                .or_insert_with(|| ReedSolomon::new(k, r).expect("k/r 已校验合法")),
        )
    }
}

// ============================================================
// 发送端
// ============================================================

/// 一个待关闭的分组
struct OpenGroup {
    id: u32,
    shards: Vec<Vec<u8>>,
    opened_at: Instant,
    max_len: usize,
}

/// FEC 编码器。每个对端一个。
pub struct FecEncoder {
    group_id: u32,
    open: Option<OpenGroup>,
    codecs: CodecCache,
    redundancy: Redundancy,
    /// 已发出的 parity 报文数（遥测）
    pub parity_sent: u64,
    /// 已关闭的分组数（遥测）
    pub groups_sent: u64,
}

impl Default for FecEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FecEncoder {
    pub fn new() -> Self {
        Self {
            group_id: 0,
            open: None,
            codecs: CodecCache::default(),
            redundancy: LADDER[DEFAULT_LEVEL],
            parity_sent: 0,
            groups_sent: 0,
        }
    }

    pub fn set_redundancy(&mut self, redundancy: Redundancy) {
        self.redundancy = redundancy;
    }

    pub fn redundancy(&self) -> Redundancy {
        self.redundancy
    }

    /// 把一个 sealed 报文纳入 FEC 保护，返回**应立即发出**的数据报。
    ///
    /// 注意：这里绝不缓冲——返回的数据报调用方必须马上发，
    /// 攒组只是为了之后算 parity。
    pub fn push(&mut self, sealed: &[u8], now: Instant) -> Vec<u8> {
        let group = self.open.get_or_insert_with(|| {
            let id = self.group_id;
            self.group_id = self.group_id.wrapping_add(1) & 0x00FF_FFFF;
            OpenGroup {
                id,
                shards: Vec::new(),
                opened_at: now,
                max_len: 0,
            }
        });
        let index = group.shards.len() as u8;
        let group_id = group.id;
        group.shards.push(sealed.to_vec());
        group.max_len = group.max_len.max(sealed.len());

        let mut out = Vec::with_capacity(DATA_HEADER_LEN + sealed.len());
        out.push(FEC_MARKER | TYPE_DATA);
        out.extend_from_slice(&group_id.to_be_bytes()[1..]); // 低 3 字节
        out.push(index);
        out.extend_from_slice(sealed);
        out
    }

    /// 分组是否已经该关了（攒够 k 个，或开启超过 flush 间隔）
    pub fn should_close(&self, now: Instant) -> bool {
        match &self.open {
            None => false,
            Some(g) => {
                g.shards.len() >= self.redundancy.k
                    || now.duration_since(g.opened_at) >= GROUP_FLUSH_INTERVAL
            }
        }
    }

    /// 关闭当前分组并产出校验报文。调用方负责发送。
    pub fn close_group(&mut self) -> Vec<Vec<u8>> {
        let Some(group) = self.open.take() else {
            return Vec::new();
        };
        let k = group.shards.len();
        let r = self.redundancy.r;
        if k == 0 {
            return Vec::new();
        }
        let Some(codec) = self.codecs.get(k, r) else {
            return Vec::new();
        };

        let shard_size = group.max_len + LEN_PREFIX;
        // 数据分片：[真实长度:2][sealed][零填充]
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + r);
        for sealed in &group.shards {
            let mut s = vec![0u8; shard_size];
            s[..LEN_PREFIX].copy_from_slice(&(sealed.len() as u16).to_be_bytes());
            s[LEN_PREFIX..LEN_PREFIX + sealed.len()].copy_from_slice(sealed);
            shards.push(s);
        }
        for _ in 0..r {
            shards.push(vec![0u8; shard_size]);
        }
        if codec.encode(&mut shards).is_err() {
            return Vec::new();
        }

        self.groups_sent += 1;
        let mut out = Vec::with_capacity(r);
        for (j, parity) in shards[k..].iter().enumerate() {
            let mut d = Vec::with_capacity(PARITY_HEADER_LEN + shard_size);
            d.push(FEC_MARKER | TYPE_PARITY);
            d.extend_from_slice(&group.id.to_be_bytes()[1..]);
            d.push((k + j) as u8);
            d.push(k as u8);
            d.push(r as u8);
            d.extend_from_slice(&(shard_size as u16).to_be_bytes());
            d.extend_from_slice(parity);
            out.push(d);
            self.parity_sent += 1;
        }
        out
    }
}

// ============================================================
// 接收端
// ============================================================

struct GroupBuf {
    /// 按 index 存放分片；数据分片存的是**补齐后**的形式
    shards: Vec<Option<Vec<u8>>>,
    k: usize,
    r: usize,
    shard_size: usize,
    /// 直接收到的数据分片下标（这些已经交付过，恢复时不要重复交付）
    delivered: Vec<bool>,
    created: Instant,
    /// 参数是否已知（要等第一个 parity 到达才知道 k/r/shard_size）
    known: bool,
    finished: bool,
    /// 参数未知时先把数据分片暂存原文
    pending_data: Vec<(u8, Vec<u8>)>,
}

impl GroupBuf {
    fn new(now: Instant) -> Self {
        Self {
            shards: Vec::new(),
            k: 0,
            r: 0,
            shard_size: 0,
            delivered: Vec::new(),
            created: now,
            known: false,
            finished: false,
            pending_data: Vec::new(),
        }
    }

    fn learn_params(&mut self, k: usize, r: usize, shard_size: usize) {
        if self.known {
            return;
        }
        self.k = k;
        self.r = r;
        self.shard_size = shard_size;
        self.shards = vec![None; k + r];
        self.delivered = vec![false; k + r];
        self.known = true;
        // 把此前暂存的数据分片补齐进来
        let pending = std::mem::take(&mut self.pending_data);
        for (idx, sealed) in pending {
            self.put_data(idx, &sealed);
        }
    }

    fn put_data(&mut self, index: u8, sealed: &[u8]) {
        if !self.known {
            self.pending_data.push((index, sealed.to_vec()));
            return;
        }
        let i = index as usize;
        if i >= self.k || sealed.len() + LEN_PREFIX > self.shard_size {
            return;
        }
        let mut s = vec![0u8; self.shard_size];
        s[..LEN_PREFIX].copy_from_slice(&(sealed.len() as u16).to_be_bytes());
        s[LEN_PREFIX..LEN_PREFIX + sealed.len()].copy_from_slice(sealed);
        self.shards[i] = Some(s);
        self.delivered[i] = true;
    }

    fn put_parity(&mut self, index: u8, parity: &[u8]) {
        let i = index as usize;
        if !self.known || i >= self.k + self.r || parity.len() != self.shard_size {
            return;
        }
        self.shards[i] = Some(parity.to_vec());
    }

    fn present(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }

    /// 数据分片是否已经齐了（齐了就没什么可恢复的，直接释放）
    fn data_complete(&self) -> bool {
        self.known && self.delivered[..self.k].iter().all(|d| *d)
    }
}

/// 恢复出来的报文
pub struct Recovered {
    pub sealed: Vec<u8>,
}

/// FEC 解码器。每个对端一个，只被单个接收任务访问，无需加锁。
pub struct FecDecoder {
    groups: HashMap<u32, GroupBuf>,
    order: VecDeque<u32>,
    codecs: CodecCache,
    /// 累计成功恢复的包数（遥测）
    pub recovered_total: u64,
    /// 累计不可恢复的分组数（遥测）
    pub unrecoverable_groups: u64,
    /// 本反馈窗口内恢复的包数
    pub recovered_window: u32,
}

impl Default for FecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析一个 FEC 数据报的结果
pub enum Incoming {
    /// 立即可交付的 sealed 报文（直达的数据分片）
    Data(Vec<u8>),
    /// HELLO：对端支持 FEC
    Hello,
    /// 对端回传的链路观测
    Control(FeedbackReport),
    /// 校验报文，本身不产生输出
    Parity,
    /// 无法解析
    Invalid,
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            order: VecDeque::new(),
            codecs: CodecCache::default(),
            recovered_total: 0,
            unrecoverable_groups: 0,
            recovered_window: 0,
        }
    }

    fn slot(&mut self, id: u32, now: Instant) -> &mut GroupBuf {
        if !self.groups.contains_key(&id) {
            if self.groups.len() >= MAX_OPEN_GROUPS {
                if let Some(oldest) = self.order.pop_front() {
                    self.groups.remove(&oldest);
                }
            }
            self.groups.insert(id, GroupBuf::new(now));
            self.order.push_back(id);
        }
        self.groups.get_mut(&id).expect("刚插入过")
    }

    /// 解析一个 FEC 数据报。返回可立即交付的内容；
    /// 恢复出来的报文通过 `take_recovered` 取。
    pub fn accept(&mut self, datagram: &[u8], now: Instant) -> Incoming {
        let Some(flags) = flags_of(datagram) else {
            return Incoming::Invalid;
        };
        match packet_type(flags) {
            TYPE_HELLO => Incoming::Hello,
            TYPE_CONTROL => match FeedbackReport::decode(datagram) {
                Some(r) => Incoming::Control(r),
                None => Incoming::Invalid,
            },
            TYPE_DATA => {
                if datagram.len() <= DATA_HEADER_LEN {
                    return Incoming::Invalid;
                }
                let id = u32::from_be_bytes([0, datagram[1], datagram[2], datagram[3]]);
                let index = datagram[4];
                let sealed = &datagram[DATA_HEADER_LEN..];
                let g = self.slot(id, now);
                if !g.finished {
                    g.put_data(index, sealed);
                }
                Incoming::Data(sealed.to_vec())
            }
            TYPE_PARITY => {
                if datagram.len() <= PARITY_HEADER_LEN {
                    return Incoming::Invalid;
                }
                let id = u32::from_be_bytes([0, datagram[1], datagram[2], datagram[3]]);
                let index = datagram[4];
                let k = datagram[5] as usize;
                let r = datagram[6] as usize;
                let shard_size = u16::from_be_bytes([datagram[7], datagram[8]]) as usize;
                let parity = &datagram[PARITY_HEADER_LEN..];
                if k == 0 || r == 0 || k + r > 255 || parity.len() != shard_size {
                    return Incoming::Invalid;
                }
                let g = self.slot(id, now);
                if !g.finished {
                    g.learn_params(k, r, shard_size);
                    g.put_parity(index, parity);
                }
                Incoming::Parity
            }
            _ => Incoming::Invalid,
        }
    }

    /// 尝试恢复所有可恢复的分组，并清理过期分组。
    pub fn take_recovered(&mut self, now: Instant) -> Vec<Recovered> {
        let mut out = Vec::new();
        let ids: Vec<u32> = self.groups.keys().copied().collect();
        for id in ids {
            let Some(g) = self.groups.get_mut(&id) else {
                continue;
            };
            if g.finished || !g.known {
                continue;
            }
            // 数据分片已齐：没什么可恢复的，直接收工
            if g.data_complete() {
                g.finished = true;
                continue;
            }
            // 分片数不够，还得再等
            if g.present() < g.k {
                continue;
            }
            let (k, r, shard_size) = (g.k, g.r, g.shard_size);
            let Some(codec) = self.codecs.get(k, r) else {
                g.finished = true;
                continue;
            };
            let mut shards = std::mem::take(&mut g.shards);
            if codec.reconstruct_data(&mut shards).is_err() {
                g.shards = shards;
                g.finished = true;
                self.unrecoverable_groups += 1;
                continue;
            }
            for i in 0..k {
                if g.delivered[i] {
                    continue; // 直达过，别重复交付
                }
                let Some(shard) = &shards[i] else { continue };
                if shard.len() < LEN_PREFIX {
                    continue;
                }
                let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
                if len == 0 || len + LEN_PREFIX > shard_size {
                    continue;
                }
                out.push(Recovered {
                    sealed: shard[LEN_PREFIX..LEN_PREFIX + len].to_vec(),
                });
                self.recovered_total += 1;
                self.recovered_window += 1;
            }
            g.shards = shards;
            g.finished = true;
        }
        self.expire(now);
        out
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .groups
            .iter()
            .filter(|(_, g)| g.finished || now.duration_since(g.created) > GROUP_DEADLINE)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(g) = self.groups.remove(&id) {
                if !g.finished && g.known && !g.data_complete() {
                    self.unrecoverable_groups += 1;
                }
            }
            if let Some(pos) = self.order.iter().position(|x| *x == id) {
                self.order.remove(pos);
            }
        }
    }
}

// ============================================================
// 入方向丢包测量
// ============================================================

/// 基于 overlay 计数器空洞的**入方向**丢包测量。
///
/// # 为什么不用 QUIC 的路径统计
///
/// `quinn` 的 `path.lost_packets` 测的是"**我发出去**的包丢了多少"（出方向），
/// 而毁掉游戏体验的是"对端发给我、我没收到"的包（入方向）——那个数据只存在于
/// **对端**的 QUIC 栈里，本地怎么读都读不到。
///
/// overlay 计数器则天然是端到端、入方向的：中继模式下也照样准，
/// 因为它是发送端在加密时打上的，中继换几段都不影响。
pub struct LossTracker {
    window_start_counter: u64,
    highest: u64,
    received: u64,
    started: Instant,
    seen_any: bool,
}

impl Default for LossTracker {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl LossTracker {
    pub fn new(now: Instant) -> Self {
        Self {
            window_start_counter: 0,
            highest: 0,
            received: 0,
            started: now,
            seen_any: false,
        }
    }

    /// 记录一个成功交付的报文的计数器。
    ///
    /// **经 FEC 恢复的包也要走这里**——它确实交付了，只是绕了一圈。
    /// 二者的区分交给 `settle` 的 `recovered_in_window` 参数：
    /// 残余丢包只看"根本没交付"的，原始丢包才把被救回的那部分加回去。
    pub fn on_received(&mut self, counter: u64) {
        if !self.seen_any {
            self.window_start_counter = counter;
            self.highest = counter;
            self.seen_any = true;
        }
        self.highest = self.highest.max(counter);
        self.received += 1;
    }

    /// 窗口是否该结算了
    pub fn window_due(&self, now: Instant) -> bool {
        self.seen_any && now.duration_since(self.started) >= LOSS_WINDOW
    }

    /// 结算窗口，返回本窗口的观测；同时开启新窗口。
    ///
    /// `recovered_in_window` 由解码器提供：原始丢包里被 FEC 救回来的那部分。
    pub fn settle(&mut self, now: Instant, recovered_in_window: u32) -> FeedbackReport {
        let span = self.highest.saturating_sub(self.window_start_counter) + 1;
        let received = self.received.min(span);
        let missing = span - received;
        // received 里含被恢复的包，原始丢包 = 缺失 + 被救回的
        let raw_missing = missing + recovered_in_window as u64;
        let window_ms = now.duration_since(self.started).as_millis().min(65535) as u16;

        let to_bp = |num: u64, den: u64| -> u16 {
            if den == 0 {
                0
            } else {
                ((num.saturating_mul(10_000)) / den).min(10_000) as u16
            }
        };
        let report = FeedbackReport {
            raw_loss_bp: to_bp(raw_missing, span),
            residual_loss_bp: to_bp(missing, span),
            recovered: recovered_in_window.min(u16::MAX as u32) as u16,
            window_ms,
        };

        self.window_start_counter = self.highest + 1;
        self.received = 0;
        self.started = now;
        report
    }
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    /// 传统格式首字节恒为 0，绝不能被误判成 FEC 格式——
    /// 这是新旧版本互通的地基，一旦破坏所有旧客户端都会断。
    #[test]
    fn legacy_datagrams_are_never_mistaken_for_fec() {
        // 传统格式 = [8 字节大端计数器][密文]
        for counter in [0u64, 1, 1000, u32::MAX as u64, 1 << 55] {
            let mut d = counter.to_be_bytes().to_vec();
            d.extend_from_slice(b"ciphertext");
            assert!(!is_fec(&d), "counter={} 被误判为 FEC 格式", counter);
        }
    }

    #[test]
    fn fec_datagrams_are_recognised() {
        assert!(is_fec(&hello_datagram()));
        assert!(is_fec(&FeedbackReport::default().encode()));
        let mut enc = FecEncoder::new();
        assert!(is_fec(&enc.push(b"payload", now())));
    }

    #[test]
    fn feedback_report_roundtrips() {
        let r = FeedbackReport {
            raw_loss_bp: 1234,
            residual_loss_bp: 56,
            recovered: 78,
            window_ms: 2000,
        };
        assert_eq!(FeedbackReport::decode(&r.encode()), Some(r));
    }

    /// 无丢包时，直达分片就该把数据补齐，不该产生任何"恢复"动作
    #[test]
    fn clean_delivery_recovers_nothing() {
        let mut enc = FecEncoder::new();
        enc.set_redundancy(Redundancy::new(4, 2));
        let mut dec = FecDecoder::new();
        let t = now();

        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 100 + i as usize]).collect();
        for p in &payloads {
            let d = enc.push(p, t);
            match dec.accept(&d, t) {
                Incoming::Data(sealed) => assert_eq!(&sealed, p),
                _ => panic!("应解析为 Data"),
            }
        }
        for parity in enc.close_group() {
            assert!(matches!(dec.accept(&parity, t), Incoming::Parity));
        }
        assert!(dec.take_recovered(t).is_empty());
        assert_eq!(dec.recovered_total, 0);
    }

    /// 丢 r 个数据分片必须能完整恢复——这是整个方案的核心承诺
    #[test]
    fn recovers_up_to_r_lost_data_shards() {
        for lost in 1..=2usize {
            let mut enc = FecEncoder::new();
            enc.set_redundancy(Redundancy::new(4, 2));
            let mut dec = FecDecoder::new();
            let t = now();

            let payloads: Vec<Vec<u8>> = (0..4u8)
                .map(|i| vec![i.wrapping_mul(7); 40 + i as usize * 30])
                .collect();
            let datagrams: Vec<Vec<u8>> = payloads.iter().map(|p| enc.push(p, t)).collect();
            let parities = enc.close_group();

            // 丢掉前 `lost` 个数据分片
            for d in datagrams.iter().skip(lost) {
                dec.accept(d, t);
            }
            for p in &parities {
                dec.accept(p, t);
            }

            let recovered = dec.take_recovered(t);
            assert_eq!(recovered.len(), lost, "丢 {} 个应恢复 {} 个", lost, lost);
            for (i, rec) in recovered.iter().enumerate() {
                assert_eq!(rec.sealed, payloads[i], "恢复出的内容必须逐字节一致");
            }
        }
    }

    /// 丢超过 r 个就该老实承认恢复不了，而不是吐出垃圾
    #[test]
    fn gives_up_beyond_r_losses() {
        let mut enc = FecEncoder::new();
        enc.set_redundancy(Redundancy::new(4, 2));
        let mut dec = FecDecoder::new();
        let t = now();

        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 80]).collect();
        let datagrams: Vec<Vec<u8>> = payloads.iter().map(|p| enc.push(p, t)).collect();
        let parities = enc.close_group();

        // 丢 3 个数据分片，只有 2 个校验分片 → 恢复不了
        dec.accept(&datagrams[3], t);
        for p in &parities {
            dec.accept(p, t);
        }
        assert!(dec.take_recovered(t).is_empty());
    }

    /// 校验报文先于数据报文到达（乱序）也必须能正常恢复
    #[test]
    fn parity_arriving_before_data_still_recovers() {
        let mut enc = FecEncoder::new();
        enc.set_redundancy(Redundancy::new(4, 2));
        let mut dec = FecDecoder::new();
        let t = now();

        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i + 1; 60]).collect();
        let datagrams: Vec<Vec<u8>> = payloads.iter().map(|p| enc.push(p, t)).collect();
        let parities = enc.close_group();

        // 先喂 parity，再喂数据（丢掉第 0 个）
        for p in &parities {
            dec.accept(p, t);
        }
        for d in datagrams.iter().skip(1) {
            dec.accept(d, t);
        }
        let recovered = dec.take_recovered(t);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].sealed, payloads[0]);
    }

    /// 稀疏流量：定时器关组时组内只有 1 个包，退化成冗余双发
    #[test]
    fn sparse_group_degrades_to_duplication() {
        let mut enc = FecEncoder::new();
        enc.set_redundancy(Redundancy::new(8, 1));
        let mut dec = FecDecoder::new();
        let t = now();

        let payload = b"lonely game packet";
        let _data = enc.push(payload, t);
        let parities = enc.close_group();
        assert_eq!(parities.len(), 1, "k'=1,r=1 应产出 1 个校验报文");

        // 数据报整个丢了，只靠校验报文恢复
        for p in &parities {
            dec.accept(p, t);
        }
        let recovered = dec.take_recovered(t);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].sealed, payload);
    }

    #[test]
    fn group_closes_on_size_or_timer() {
        let mut enc = FecEncoder::new();
        enc.set_redundancy(Redundancy::new(4, 2));
        let t = now();
        assert!(!enc.should_close(t), "空组不需要关");

        enc.push(b"a", t);
        assert!(!enc.should_close(t), "才 1 个包且没超时");
        assert!(
            enc.should_close(t + GROUP_FLUSH_INTERVAL),
            "超过 flush 间隔就该关组，否则稀疏流量永远等不到 parity"
        );

        for _ in 0..3 {
            enc.push(b"a", t);
        }
        assert!(enc.should_close(t), "攒够 k 个立即关组");
    }

    #[test]
    fn oversized_group_count_is_bounded() {
        let mut dec = FecDecoder::new();
        let t = now();
        // 灌入远超上限的分组
        for id in 0..(MAX_OPEN_GROUPS * 3) {
            let mut d = vec![FEC_MARKER | TYPE_DATA];
            d.extend_from_slice(&(id as u32).to_be_bytes()[1..]);
            d.push(0);
            d.extend_from_slice(b"x");
            dec.accept(&d, t);
        }
        assert!(
            dec.groups.len() <= MAX_OPEN_GROUPS,
            "分组数必须有上限，否则对端可以伪造 group_id 打爆内存"
        );
    }

    #[test]
    fn stale_groups_expire() {
        let mut dec = FecDecoder::new();
        let t = now();
        let mut d = vec![FEC_MARKER | TYPE_DATA, 0, 0, 1, 0];
        d.extend_from_slice(b"payload");
        dec.accept(&d, t);
        assert_eq!(dec.groups.len(), 1);
        dec.take_recovered(t + GROUP_DEADLINE + Duration::from_millis(1));
        assert!(dec.groups.is_empty(), "过期分组必须回收");
    }

    #[test]
    fn malformed_datagrams_are_rejected() {
        let mut dec = FecDecoder::new();
        let t = now();
        assert!(matches!(dec.accept(&[], t), Incoming::Invalid));
        // DATA 头但没有载荷
        assert!(matches!(
            dec.accept(&[FEC_MARKER | TYPE_DATA, 0, 0, 0, 0], t),
            Incoming::Invalid
        ));
        // PARITY 声明的 shard_size 与实际不符
        let bad = vec![FEC_MARKER | TYPE_PARITY, 0, 0, 0, 4, 4, 2, 0, 200, 1, 2, 3];
        assert!(matches!(dec.accept(&bad, t), Incoming::Invalid));
    }

    // ---------- 丢包测量 ----------

    #[test]
    fn loss_tracker_reports_zero_on_clean_link() {
        let t = now();
        let mut lt = LossTracker::new(t);
        for c in 0..100u64 {
            lt.on_received(c);
        }
        let r = lt.settle(t + LOSS_WINDOW, 0);
        assert_eq!(r.raw_loss_bp, 0);
        assert_eq!(r.residual_loss_bp, 0);
    }

    #[test]
    fn loss_tracker_measures_gaps() {
        let t = now();
        let mut lt = LossTracker::new(t);
        // 收到 0..100 中的偶数，即丢一半
        for c in (0..100u64).step_by(2) {
            lt.on_received(c);
        }
        let r = lt.settle(t + LOSS_WINDOW, 0);
        // span=99(0..98)+1=99, received=50 → 缺 49 ≈ 49.5%
        assert!(
            (4800..=5100).contains(&r.raw_loss_bp),
            "丢一半应报 ~50%，实得 {}bp",
            r.raw_loss_bp
        );
    }

    /// 被 FEC 救回的包要算进"原始丢包"，但不算进"残余丢包"——
    /// 否则自适应会以为链路很干净，把冗余降下去，然后立刻又开始丢
    #[test]
    fn recovered_packets_count_as_raw_loss_but_not_residual() {
        let t = now();
        let mut lt = LossTracker::new(t);
        // 100 个包里有 10 个是靠 FEC 救回来的
        for c in 0..100u64 {
            lt.on_received(c);
        }
        let r = lt.settle(t + LOSS_WINDOW, 10);
        assert_eq!(r.residual_loss_bp, 0, "全恢复了，残余丢包应为 0");
        assert!(
            r.raw_loss_bp >= 900,
            "原始丢包应体现那 10% 被救回的包，实得 {}bp",
            r.raw_loss_bp
        );
    }

    // ---------- 冗余控制 ----------

    #[test]
    fn ladder_is_monotonically_stronger() {
        for w in LADDER.windows(2) {
            assert!(
                w[1].overhead_pct() > w[0].overhead_pct(),
                "档位必须单调增强，否则升档反而降冗余"
            );
        }
    }

    #[test]
    fn loss_maps_to_expected_level() {
        assert_eq!(level_for_loss(0), 0);
        assert_eq!(level_for_loss(100), 1); // 1%
        assert_eq!(level_for_loss(400), 2); // 4%
        assert_eq!(level_for_loss(1500), 3); // 15%
    }

    /// 升档必须立即——丢包已经在伤害体验了，不能慢慢来
    #[test]
    fn upgrade_is_immediate() {
        let t = now();
        let mut c = RedundancyController::new(0);
        c.level = 0;
        c.observe(
            FeedbackReport {
                raw_loss_bp: 2000,
                ..Default::default()
            },
            t,
        );
        assert_eq!(c.level(), 3, "高丢包应一步升到最强档");
    }

    /// 降档必须慢——否则链路抖动时会来回震荡
    #[test]
    fn downgrade_requires_sustained_confirmation() {
        let t = now();
        let mut c = RedundancyController::new(0);
        c.level = 3;
        for _ in 0..(DOWNGRADE_CONFIRMATIONS - 1) {
            c.observe(FeedbackReport::default(), t);
        }
        assert_eq!(c.level(), 3, "确认次数不够时不能降档");
        c.observe(FeedbackReport::default(), t);
        assert_eq!(c.level(), 2, "确认够了降一档（一次只降一级）");
    }

    #[test]
    fn manual_floor_is_respected() {
        let t = now();
        let mut c = RedundancyController::new(2);
        for _ in 0..(DOWNGRADE_CONFIRMATIONS * 5) {
            c.observe(FeedbackReport::default(), t);
        }
        assert!(c.level() >= 2, "自适应不得降到用户设定的下限以下");
    }

    #[test]
    fn stale_feedback_falls_back_to_default() {
        let t = now();
        let mut c = RedundancyController::new(0);
        c.observe(
            FeedbackReport {
                raw_loss_bp: 5000,
                ..Default::default()
            },
            t,
        );
        assert_eq!(c.level(), 3);
        c.tick(t + FEEDBACK_STALE + Duration::from_secs(1));
        assert_eq!(c.level(), DEFAULT_LEVEL, "反馈中断应回落到安全默认档");
    }
}
