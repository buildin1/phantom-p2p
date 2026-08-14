//! 补发闸门：决定"这一刻允许补几份"。
//!
//! # 为什么需要一道独立的闸门
//!
//! 分档表（`tun_bridge.rs` 的 `tier_for_bp`）回答的是"按测到的丢包率**应该**补几份"，
//! 但它有个致命前提：假设补发流量是免费的。实测证明不是——补发包和原包抢同一个
//! QUIC 数据报发送队列，队列满时 quinn 丢的是**最旧的**那个，于是副本会把还没发出去
//! 的原包挤掉。丢包率因此不降反升，档位继续往上爬，形成正反馈：
//!
//! ```text
//! 链路被占满 → 微量丢包 → 档位上调 → 副本挤掉原包 → 丢包更多 → 档位继续上调
//! ```
//!
//! 闸门回答的是另一个问题：**"现在这条链路还承受得起补发流量吗"**。它只减不增——
//! 分档表说该补 2 份，闸门可以压到 1 份或 0 份，但永远不会往上加。
//!
//! # 为什么用本地信号，而且退得比进得快
//!
//! 判断"是不是我自己把链路压垮了"这件事，本地信号是**即时且无偏**的：发送队列还剩
//! 多少空间、排队延迟涨了多少、拥塞控制器自己报了几次拥塞事件，全都不需要等对端往返，
//! 也不受对端上报延迟的影响。而丢包率要经过"对端测量 → 心跳上报"，至少慢一整个
//! 心跳周期。
//!
//! 所以：**刹车走本地信号（毫秒级），加码走丢包率（秒级）**。安全攸关的方向必须最快，
//! 这是控制系统的基本要求——上一版正好反过来，唯一的拥塞判据挂在每秒一次的心跳处理里，
//! 而且要 RTT 涨到 3 倍才触发，那时队列早就堆了近百毫秒。

use std::time::{Duration, Instant};

/// 闸门状态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate {
    /// 链路正在拥塞（或已被我们自己压垮）：完全不补。
    ///
    /// 不是"少补一点"而是"一份都不补"——判定拥塞时那一份副本恰恰**就是**丢包的来源。
    /// 而且拥塞丢包是突发的（队列溢出连丢一串），错峰几十毫秒的副本会和原包一起被
    /// 同一次溢出吞掉，物理上救不回来。这条流并没有失去保护：ARQ 照常覆盖，
    /// 而且 ARQ 在拥塞时是**自限**的（要等对端发现空洞才触发，越堵触发越慢），
    /// 冗余不是。
    Closed,
    /// 刚从拥塞里恢复，或有轻微拥塞迹象：最多补 1 份。
    Throttled,
    /// 链路宽裕：按分档表来，最多 2 份。
    Open,
}

impl Gate {
    /// 这一档允许的最大补发份数（不含原包）。
    pub fn max_extra_copies(self) -> u8 {
        match self {
            Gate::Closed => 0,
            Gate::Throttled => 1,
            Gate::Open => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Gate::Closed => "closed",
            Gate::Throttled => "throttled",
            Gate::Open => "open",
        }
    }
}

/// 触发关闸的原因，只用于日志——排障时"为什么补发被关掉了"必须一眼看出来。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TripReason {
    /// 链路干净，没有关闸
    Clean,
    /// 我们自己的发送把队列挤爆了（最硬的证据，无需推断）
    SelfEvict,
    /// 发送队列占用率过高
    Occupancy,
    /// 排队延迟上涨
    DelayGradient,
    /// 没有可用带宽余量
    NoHeadroom,
}

impl TripReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TripReason::Clean => "clean",
            TripReason::SelfEvict => "evict",
            TripReason::Occupancy => "occ",
            TripReason::DelayGradient => "grad",
            TripReason::NoHeadroom => "headroom",
        }
    }
}

/// 占用率超过这个比例进入"谨慎"，还不关闸但不许升到 Open。
///
/// **占用率不再单独作为关闸条件。** 实测证明它在 20Hz 采样下几乎没有诊断价值：
/// 一整个会话里每一条日志的 `occ` 都是 0.00，而同期本端因为队列满丢掉了 79 个包。
/// 真实的溢出是亚 50ms 尺度的突发，采样点永远落在队列已经排空之后。
/// 真正抓得住这件事的是 [`Observation::self_evicted`]——它是逐包判断的，
/// 而且一旦触发就是**不需要推断的证据**。占用率降级为"谨慎"信号和诊断量。
const OCCUPANCY_CAUTION: f32 = 0.10;

/// 排队延迟相对基线涨了这个比例就判定为拥塞。
///
/// 0.40 在 45ms 基线上约等于 18ms 站队延迟——远早于内层 TCP 的 55ms 自愈窗口，
/// 我们在 TCP 察觉之前就已经收手。
///
/// 对比被取代的旧判据 `RTT > 3 × 历史最小 RTT`：3 倍在同样的基线上是 90ms 站队，
/// 那时内层 TCP 早就重传、画面早就回弹了，**大约宽松了 5 倍**；而且它每秒只在
/// 收到心跳时算一次。
const GRADIENT_TRIP: f32 = 0.40;
const GRADIENT_CAUTION: f32 = 0.15;

/// 排队延迟的**绝对**下限：低于这个值，无论比值多大都不算拥塞。
///
/// 梯度是个比值，`rttmin` 越小，同样的绝对抖动算出来的比值越大。实测抓到过
/// `grad=0.45 srtt=12ms rttmin=8ms` 就关闸——**4 毫秒的排队延迟**，相对内层
/// TCP 的 55ms 自愈预算什么都不是，纯粹是低延迟链路上的正常抖动被比值放大了。
///
/// 分母兜底（`MinRttFilter::gradient` 里的 5ms）挡不住这种情况：那条只在
/// `rttmin` 极小时生效，而 8ms 已经超过它了。所以这里再加一道绝对门槛：
/// 排队延迟本身不到 12ms 就别谈拥塞，留给 55ms 预算足够的余量。
const MIN_QUEUEING_DELAY: Duration = Duration::from_millis(12);

/// 从 Closed 回到 Throttled 需要连续多久没有任何拥塞迹象。
const REOPEN_TO_THROTTLED: Duration = Duration::from_millis(500);
/// 从 Throttled 回到 Open 需要连续多久既没有拥塞也没有谨慎信号。
///
/// 比降档慢得多是有意的：拥塞是间歇性的，刚喘过一口气就立刻满血加码，
/// 只会在拥塞边缘反复横跳，把链路一直摁在临界点上。
const REOPEN_TO_OPEN: Duration = Duration::from_millis(2000);

/// 一次采样看到的链路状态。纯数据，不含时钟也不含锁，方便直接构造做测试。
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    /// 最近一小段时间内，是否发生过"因为队列没空间而放弃发送"。
    ///
    /// **这是整套信号里唯一不需要任何推断的**：它非零就直接证明我们自己是
    /// 丢包来源，不用比较、不用阈值、不用等对端回话。
    pub self_evicted: bool,
    /// 发送队列占用率 0.0~1.0
    pub occupancy: f32,
    /// 排队延迟梯度 `(srtt - rtt_min) / rtt_min`
    pub delay_gradient: f32,
    /// 排队延迟的绝对值 `srtt - rtt_min`。
    ///
    /// 和梯度一起用：比值负责"相对这条链路自己算不算异常"，绝对值负责
    /// "这点延迟到底值不值得在意"。缺了后者，低 RTT 链路上几毫秒的正常抖动
    /// 会被比值放大成拥塞，见 [`MIN_QUEUEING_DELAY`]。
    pub queueing_delay: Duration,
    /// 估计的可用带宽余量（字节/秒）。<= 0 表示业务流量已经把链路吃满。
    pub headroom_bps: i64,
    /// 距上次采样，拥塞控制器自己报了几次拥塞事件
    pub congestion_events: u64,
}

impl Observation {
    /// 链路干净时的观测值，用于测试和连接刚建立时的初值。
    pub fn clean() -> Self {
        Self {
            self_evicted: false,
            occupancy: 0.0,
            delay_gradient: 0.0,
            queueing_delay: Duration::ZERO,
            headroom_bps: i64::MAX,
            congestion_events: 0,
        }
    }

    /// 需要立刻关闸吗？
    fn trip_reason(&self) -> TripReason {
        // 顺序即优先级：先报最确凿的原因，日志才有诊断价值。
        if self.self_evicted {
            TripReason::SelfEvict
        } else if self.delay_gradient > GRADIENT_TRIP && self.queueing_delay >= MIN_QUEUEING_DELAY {
            // 比值和绝对值**都**要超标。少了绝对值这一半，低 RTT 链路上
            // 几毫秒的正常抖动就会关闸，见 `MIN_QUEUEING_DELAY`。
            TripReason::DelayGradient
        } else if self.headroom_bps <= 0 {
            TripReason::NoHeadroom
        } else {
            TripReason::Clean
        }
    }

    /// 还不到关闸的程度，但不该继续加码。
    fn is_cautious(&self) -> bool {
        self.occupancy > OCCUPANCY_CAUTION
            || self.delay_gradient > GRADIENT_CAUTION
            || self.congestion_events > 0
    }
}

/// 闸门状态机。
///
/// 纯逻辑：不读时钟、不加锁、不碰网络。`now` 由调用方传进来，所以整套升降档时序
/// 都能在单测里精确复现，不需要真建一条 QUIC 连接，也不需要 sleep。
pub struct GateController {
    state: Gate,
    /// 连续无 trip 的起点；`None` 表示当前就处在 trip 状态
    clean_since: Option<Instant>,
    /// 连续无 caution 的起点
    calm_since: Option<Instant>,
    last_reason: TripReason,
}

impl GateController {
    /// 从 `Open` 起步：不预设链路有问题，跟"链路默认是干净的"这个假设一致。
    pub fn new() -> Self {
        Self {
            state: Gate::Open,
            clean_since: None,
            calm_since: None,
            last_reason: TripReason::Clean,
        }
    }

    pub fn state(&self) -> Gate {
        self.state
    }

    pub fn last_reason(&self) -> TripReason {
        self.last_reason
    }

    /// 推进一步，返回这一刻的闸门状态。
    pub fn step(&mut self, obs: &Observation, now: Instant) -> Gate {
        let reason = obs.trip_reason();
        self.last_reason = reason;

        if reason != TripReason::Clean {
            // 降档永远是**立即**的，不需要任何驻留时间。
            self.state = Gate::Closed;
            self.clean_since = None;
            self.calm_since = None;
            return self.state;
        }

        // 驻留期从**第一次观测到干净的那一刻**起算，不是从关闸那一刻。
        // 采样是离散的，关闸和下一次干净采样之间链路究竟何时恢复无从得知，
        // 按观测时刻起算是保守的那一侧（宁可晚放开）。
        let clean_since = *self.clean_since.get_or_insert(now);
        if obs.is_cautious() {
            self.calm_since = None;
        } else {
            self.calm_since.get_or_insert(now);
        }

        self.state = match self.state {
            Gate::Closed => {
                if now.duration_since(clean_since) >= REOPEN_TO_THROTTLED {
                    Gate::Throttled
                } else {
                    Gate::Closed
                }
            }
            Gate::Throttled => match self.calm_since {
                Some(calm) if now.duration_since(calm) >= REOPEN_TO_OPEN => Gate::Open,
                _ => Gate::Throttled,
            },
            // 已经是 Open：只要没 trip 就保持
            Gate::Open => Gate::Open,
        };
        self.state
    }
}

impl Default for GateController {
    fn default() -> Self {
        Self::new()
    }
}

/// 滑动窗口最小 RTT。
///
/// **不能用"这条连接见过的历史最小值"**——那是上一版的做法，它单调不增，于是：
/// 连接建立时一个走运的低采样会**永久**毒化基线，之后所有的梯度都相对那个不真实的
/// 低点算；而路由变更导致基线合法抬升（换 Wi-Fi、切基站）时，又永远学不到新基线，
/// 整条连接余下的时间里都会被误判成"一直在拥塞"。
///
/// 按桶存最小值，窗口滚动淘汰，跟 BBR 的 min_rtt 过滤器同一个思路。
pub struct MinRttFilter {
    /// (桶的起始时刻, 该桶内的最小值)
    buckets: Vec<(Instant, Duration)>,
    bucket_span: Duration,
    window: Duration,
}

impl MinRttFilter {
    /// `window` 是整个观测窗口，`bucket_span` 是每个桶的时间跨度。
    pub fn new(window: Duration, bucket_span: Duration) -> Self {
        Self {
            buckets: Vec::new(),
            bucket_span,
            window,
        }
    }

    pub fn observe(&mut self, rtt: Duration, now: Instant) {
        match self.buckets.last_mut() {
            Some((start, min)) if now.duration_since(*start) < self.bucket_span => {
                if rtt < *min {
                    *min = rtt;
                }
            }
            _ => self.buckets.push((now, rtt)),
        }
        self.buckets
            .retain(|(start, _)| now.duration_since(*start) <= self.window);
    }

    /// 当前窗口内的最小 RTT；还没有任何样本时返回 `None`。
    pub fn get(&self) -> Option<Duration> {
        self.buckets.iter().map(|(_, m)| *m).min()
    }

    /// 相对基线的排队延迟梯度。没有基线时返回 0（不预设拥塞）。
    ///
    /// 分母兜底 5ms：本机回环之类的极低 RTT 链路上，几毫秒的正常抖动会被放大成
    /// 巨大的梯度，凭空触发关闸。
    pub fn gradient(&self, current: Duration) -> f32 {
        let Some(min) = self.get() else {
            return 0.0;
        };
        let floor = min.max(Duration::from_millis(5));
        let excess = current.saturating_sub(min);
        excess.as_secs_f32() / floor.as_secs_f32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn congested() -> Observation {
        Observation {
            self_evicted: true,
            ..Observation::clean()
        }
    }

    /// 自挤占是最硬的证据：必须**立即**关闸，不能有任何驻留期。
    #[test]
    fn gate_closes_immediately_on_self_eviction() {
        let t = Instant::now();
        let mut g = GateController::new();
        assert_eq!(g.step(&Observation::clean(), t), Gate::Open);
        assert_eq!(g.step(&congested(), t), Gate::Closed);
        assert_eq!(g.last_reason(), TripReason::SelfEvict);
        assert_eq!(Gate::Closed.max_extra_copies(), 0, "拥塞时必须一份都不补");
    }

    /// 恢复必须是分级的、慢的。刚喘一口气就满血加码，只会在拥塞边缘反复横跳。
    ///
    /// 注意驻留期的起点是**第一次观测到干净的那一刻**，不是关闸那一刻——
    /// 采样是离散的（50ms 一次），关闸和下一次干净采样之间链路到底什么时候
    /// 恢复的，我们并不知道。按观测到的时刻起算是保守的那一侧。
    #[test]
    fn gate_requires_full_dwell_before_reopening() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let clean = Observation::clean();
        let mut g = GateController::new();
        g.step(&congested(), t);
        assert_eq!(g.state(), Gate::Closed);

        // t+400 第一次看到干净：驻留期从这里开始计时，本次仍然关着
        assert_eq!(g.step(&clean, t + ms(400)), Gate::Closed);
        // 距起点才 400ms，不够
        assert_eq!(g.step(&clean, t + ms(800)), Gate::Closed);
        // 距起点满 500ms：升到 Throttled，但只允许 1 份
        assert_eq!(g.step(&clean, t + ms(900)), Gate::Throttled);
        assert_eq!(Gate::Throttled.max_extra_copies(), 1);
        // 距平静起点不满 2 秒：还不能到 Open
        assert_eq!(g.step(&clean, t + ms(2000)), Gate::Throttled);
        // 满 2 秒才放开
        assert_eq!(g.step(&clean, t + ms(2400)), Gate::Open);
    }

    /// 任何 trip 都要把状态一路打回 Closed，不是逐级下降。
    #[test]
    fn gate_drops_straight_to_closed_from_open() {
        let t = Instant::now();
        let mut g = GateController::new();
        assert_eq!(g.step(&Observation::clean(), t), Gate::Open);
        let obs = Observation {
            headroom_bps: 0,
            ..Observation::clean()
        };
        assert_eq!(g.step(&obs, t), Gate::Closed);
        assert_eq!(g.last_reason(), TripReason::NoHeadroom);
    }

    /// **低 RTT 链路上的小抖动不得关闸。**
    ///
    /// 实测抓到过 `grad=0.45 srtt=12ms rttmin=8ms` 就关闸——4 毫秒的排队延迟，
    /// 相对内层 TCP 的 55ms 自愈预算什么都不是。梯度是比值，`rttmin` 越小越容易
    /// 被正常抖动顶过阈值，所以必须同时看绝对值。
    #[test]
    fn a_few_milliseconds_of_queueing_never_trips_the_gate() {
        let t = Instant::now();
        let mut g = GateController::new();
        let obs = Observation {
            // 比值远超阈值……
            delay_gradient: 0.45,
            // ……但绝对排队延迟只有 4ms
            queueing_delay: Duration::from_millis(4),
            ..Observation::clean()
        };
        assert_eq!(
            g.step(&obs, t),
            Gate::Open,
            "4ms 排队不该被当成拥塞，哪怕比值到了 0.45"
        );
    }

    /// 反过来：比值和绝对值都超标时必须关闸。
    #[test]
    fn real_queue_buildup_still_trips_the_gate() {
        let t = Instant::now();
        let mut g = GateController::new();
        let obs = Observation {
            delay_gradient: 0.8,
            queueing_delay: Duration::from_millis(30),
            ..Observation::clean()
        };
        assert_eq!(g.step(&obs, t), Gate::Closed);
        assert_eq!(g.last_reason(), TripReason::DelayGradient);
    }

    /// 占用率单独不再关闸——20Hz 采样看不见亚 50ms 的突发溢出，
    /// 实测一整个会话 `occ` 恒为 0.00 而本端丢了 79 个包。
    #[test]
    fn occupancy_alone_no_longer_trips_the_gate() {
        let t = Instant::now();
        let mut g = GateController::new();
        let obs = Observation {
            occupancy: 0.9,
            ..Observation::clean()
        };
        assert_eq!(
            g.step(&obs, t),
            Gate::Open,
            "占用率只当谨慎信号，真正抓突发的是 self_evicted"
        );
    }

    /// **误触发防护。** 一个会在干净链路上乱关闸的控制器，等于把整个补包功能
    /// 静默废掉，而且没人会发现——比不加控制器更糟。
    #[test]
    fn gate_never_trips_on_a_clean_idle_link() {
        let t = Instant::now();
        let mut g = GateController::new();
        for i in 0..600 {
            let now = t + Duration::from_millis(i * 50);
            assert_eq!(
                g.step(&Observation::clean(), now),
                Gate::Open,
                "干净链路第 {} 次采样不该关闸",
                i
            );
        }
    }

    /// 余量耗尽本身就是关闸理由：源速率已经把链路吃满时，补发无处可去。
    #[test]
    fn no_headroom_closes_the_gate() {
        let t = Instant::now();
        let mut g = GateController::new();
        let obs = Observation {
            headroom_bps: 0,
            ..Observation::clean()
        };
        assert_eq!(g.step(&obs, t), Gate::Closed);
        assert_eq!(g.last_reason(), TripReason::NoHeadroom);
    }

    /// 谨慎信号不关闸，但要卡住"升到 Open"这一步。
    #[test]
    fn caution_holds_the_gate_at_throttled() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let clean = Observation::clean();
        let mut g = GateController::new();
        g.step(&congested(), t);
        // 驻留期从第一次看到干净（t+500）起算，满 500ms 后升到 Throttled
        g.step(&clean, t + ms(500));
        assert_eq!(g.step(&clean, t + ms(1000)), Gate::Throttled);

        // 此后持续有轻微拥塞迹象：即使过很久也只能停在 Throttled，
        // 不能一路升到 Open——占用率 0.15 说明队列一直有存货。
        let cautious = Observation {
            occupancy: 0.15,
            ..Observation::clean()
        };
        for i in 1..100 {
            let now = t + ms(1000 + i * 50);
            assert_eq!(
                g.step(&cautious, now),
                Gate::Throttled,
                "第 {} 次采样仍有谨慎信号，不该升到 Open",
                i
            );
        }
    }

    /// 基线必须能跟着链路真实情况抬升。
    ///
    /// 上一版用的是全时最小值，单调不增：换网络导致 RTT 合法抬高之后，
    /// 梯度会永远相对那个再也达不到的旧低点计算，于是连接余下的时间里
    /// 一直被误判成拥塞。
    #[test]
    fn windowed_min_rtt_recovers_after_a_baseline_shift() {
        let t = Instant::now();
        let mut f = MinRttFilter::new(Duration::from_secs(10), Duration::from_secs(1));

        // 一开始是条 10ms 的链路
        f.observe(Duration::from_millis(10), t);
        assert_eq!(f.get(), Some(Duration::from_millis(10)));

        // 换网之后基线真的变成 100ms，持续 12 秒（超过窗口）
        for i in 1..=12 {
            f.observe(Duration::from_millis(100), t + Duration::from_secs(i));
        }
        assert_eq!(
            f.get(),
            Some(Duration::from_millis(100)),
            "旧的 10ms 应已滑出窗口，基线要跟上来"
        );
        assert!(
            f.gradient(Duration::from_millis(100)) < 0.01,
            "在新基线上稳定运行不该被判成拥塞"
        );
    }

    /// 极低 RTT 链路上的正常抖动不能被放大成拥塞。
    #[test]
    fn tiny_rtt_jitter_does_not_look_like_congestion() {
        let t = Instant::now();
        let mut f = MinRttFilter::new(Duration::from_secs(10), Duration::from_secs(1));
        f.observe(Duration::from_micros(200), t);
        // 0.2ms 基线上抖到 2ms：没有 5ms 兜底的话梯度会是 9.0，直接误判
        assert!(
            f.gradient(Duration::from_millis(2)) < GRADIENT_TRIP,
            "极低 RTT 上的小抖动不该触发关闸"
        );
    }

    #[test]
    fn gradient_reports_zero_without_a_baseline() {
        let f = MinRttFilter::new(Duration::from_secs(10), Duration::from_secs(1));
        assert_eq!(f.gradient(Duration::from_millis(50)), 0.0);
    }
}
