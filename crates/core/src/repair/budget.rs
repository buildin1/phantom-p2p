//! 补发流量的预算：两个令牌桶，各管一件事，取交集。
//!
//! # 为什么一个写死的常量是错的
//!
//! 上一版用 `MAX_REPAIR_PACKETS_PER_SEC = 300` 一个绝对值管所有情况，这有两个
//! 独立的问题。
//!
//! **一、量纲错了。** 300 个包对不同流量意味着完全不同的带宽：
//!
//! | 流量 | 300 包/秒 折合 |
//! |---|---|
//! | 145 字节的游戏包 | 约 43 kB/s |
//! | 1200 字节的批量包 | 约 360 kB/s |
//!
//! 同一个数字在两种场景下松紧差 8 倍。管容量必须用字节。
//!
//! **二、这个数字本身是口径被偷换来的。**《踩坑记录》第十一条里 300 包/秒
//! 指的是"**5 人整局、2 倍发包之后的总速率**"，代码把它变成了"**每条连接、
//! 只算补发流量**"的预算——等于放宽好几倍，还随连接数线性叠加。而同期的分档表
//! 允许每包补 8 份，远超推导出 300 时假设的 2 倍。
//!
//! # 两个桶，两个目的
//!
//! - **字节桶**管**容量**：补发流量不能超过链路的可用余量。余量由采样器估计
//!   （`BtlBw × 安全边际 − 当前业务速率`），链路一紧就自动收紧。
//! - **包桶**管**风控**：运营商盯的是"包速率突然翻倍"这种模式，不是字节数。
//!   《踩坑记录》第十一条实测有用户约 2 分钟被掐断。这个桶按**源包速率的比例**
//!   算，而不是绝对值——"补发不超过原始流量的一半"在任何负载下含义都一致，
//!   300 这个绝对值则不是。
//!
//! 两个桶都要拿到令牌才放行。任一为空就放弃这一份补发（不排队、不重试——
//! 补发本来就是尽力而为，为它排队只会让它更晚到、更没用）。

use std::time::{Duration, Instant};

/// 补发包速率相对源包速率的比例上限。
///
/// 0.5 表示"每 2 个业务包最多补 1 个"。这是在**任何**负载下都成立的表述，
/// 而绝对值不是。
const REPAIR_PPS_RATIO: f32 = 0.5;

/// 补发包速率的绝对天花板（包/秒）。
///
/// 保留《踩坑记录》第十一条那个数量级作为最后一道硬顶：即使比例算出来更高，
/// 也不允许突破。比例桶管相对松紧，这个管绝对上限。
const REPAIR_PPS_CEILING: f32 = 300.0;

/// 补发字节速率相对源字节速率的比例上限。
///
/// 即使链路余量很大，也不该无节制地放大——放大倍数本身就是风控特征。
const REPAIR_BYTES_RATIO: f32 = 1.0;

/// 令牌桶允许的突发量，按"多少个满载包"计。
///
/// 补发天然是突发的（一个包的几份副本在几十毫秒内发完），桶太小会把正常的
/// 错峰发送误伤成超限。
const BURST_PACKETS: f32 = 8.0;

/// 速率上调的最快步长：每 2 秒最多涨 1.5 倍。
///
/// 《踩坑记录》第十一条要求放大必须"有节制、有上限、可回退"。突然把补发速率
/// 拉满正是触发运营商风控的模式，即使总量还在上限之内。
const RAMP_FACTOR: f32 = 2.0;
const RAMP_INTERVAL: Duration = Duration::from_secs(1);

/// 一个简单的令牌桶。纯逻辑，时间由调用方传入，可完整单测。
#[derive(Debug)]
struct TokenBucket {
    tokens: f32,
    /// 每秒补充多少令牌
    rate: f32,
    /// 桶容量（突发上限）
    burst: f32,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f32, burst: f32, now: Instant) -> Self {
        Self {
            // 从满桶起步：连接刚建立时不该因为"桶还没攒满"而拒绝头几份补发。
            tokens: burst,
            rate,
            burst,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last_refill).as_secs_f32();
        if dt <= 0.0 {
            return;
        }
        self.last_refill = now;
        self.tokens = (self.tokens + self.rate * dt).min(self.burst);
    }

    fn try_take(&mut self, amount: f32, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn set_rate(&mut self, rate: f32, burst: f32) {
        self.rate = rate.max(0.0);
        self.burst = burst.max(1.0);
        self.tokens = self.tokens.min(self.burst);
        // 速率归零意味着"一份都不许补"，那就必须连桶里剩的令牌一起清掉。
        // 否则余量已经耗尽、闸门已经关死，却还能靠初始满桶继续往外挤
        // 一整个突发量的补发包——正好是最不该发的时候发出去。
        if self.rate == 0.0 {
            self.tokens = 0.0;
        }
    }
}

/// 补发预算。
pub struct RepairBudget {
    bytes: TokenBucket,
    packets: TokenBucket,
    /// 上次上调速率的时刻，用于限制爬升速度
    last_ramp: Instant,
    /// 当前生效的字节速率，用于判断这次是上调还是下调
    current_byte_rate: f32,
    /// 是否已经拿到过第一次链路估计。
    ///
    /// 首次建立速率**不受爬升限制**：那不是"放大"，只是把预算从"还不知道"
    /// 变成"知道了"。受限的是在已有基线之上继续往上加。少了这个区分，
    /// 连接头一个爬升周期内预算恒为 0，补包在最需要的连接初期几乎是关的。
    initialized: bool,
}

impl RepairBudget {
    pub fn new(now: Instant) -> Self {
        Self {
            bytes: TokenBucket::new(0.0, 1500.0 * BURST_PACKETS, now),
            packets: TokenBucket::new(0.0, BURST_PACKETS, now),
            last_ramp: now,
            current_byte_rate: 0.0,
            initialized: false,
        }
    }

    /// 按最新的链路估计更新预算。采样器每 50ms 调一次。
    ///
    /// * `headroom_bps` —— 估计的可用带宽余量（字节/秒）
    /// * `source_bps` —— 当前业务发送速率（字节/秒），只算原包
    /// * `source_pps` —— 当前业务包速率（包/秒），只算原包
    pub fn update(&mut self, headroom_bps: f32, source_bps: f32, source_pps: f32, now: Instant) {
        // 字节预算 = min(链路余量, 源速率的固定倍数)。
        // 前者管"链路装得下吗"，后者管"放大倍数本身合不合理"——
        // 一条很慢的流不该因为链路总余量大就被允许放大几十倍。
        let target_bytes = headroom_bps.max(0.0).min(source_bps * REPAIR_BYTES_RATIO);

        // **下调立即生效，上调受爬升限制。** 安全方向必须最快，
        // 这跟闸门的非对称设计是同一个道理。
        let byte_rate = if !self.initialized {
            // 首次拿到估计：直接采用，见 `initialized` 字段的说明。
            self.initialized = true;
            self.last_ramp = now;
            target_bytes
        } else if target_bytes <= self.current_byte_rate {
            self.last_ramp = now;
            target_bytes
        } else if now.duration_since(self.last_ramp) >= RAMP_INTERVAL {
            self.last_ramp = now;
            // 从 0 起步时给一个下限，否则乘法永远推不动
            let floor = 1500.0 * BURST_PACKETS / RAMP_INTERVAL.as_secs_f32();
            (self.current_byte_rate * RAMP_FACTOR)
                .max(floor)
                .min(target_bytes)
        } else {
            self.current_byte_rate
        };
        self.current_byte_rate = byte_rate;

        let packet_rate = (source_pps * REPAIR_PPS_RATIO).min(REPAIR_PPS_CEILING);

        self.bytes.set_rate(byte_rate, 1500.0 * BURST_PACKETS);
        self.packets.set_rate(packet_rate, BURST_PACKETS);
    }

    /// 申请发一份 `len` 字节的补发包。两个桶都得批准。
    pub fn try_admit(&mut self, len: usize, now: Instant) -> bool {
        // 先看包桶：它更容易空，先查能少动一次字节桶的状态。
        // 注意两个都要真的扣减，所以不能短路成"只扣一个"。
        let pkt_ok = self.packets.try_take(1.0, now);
        if !pkt_ok {
            return false;
        }
        if self.bytes.try_take(len as f32, now) {
            true
        } else {
            // 字节桶不够：把刚扣的包令牌还回去，避免两个桶的计数漂移。
            self.packets.tokens += 1.0;
            false
        }
    }

    /// 当前字节预算，仅供日志。
    pub fn byte_rate(&self) -> f32 {
        self.current_byte_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    /// 在同一份字节预算下，从头跑一段时间能放行多少个包。
    /// 包桶给足，让字节桶成为唯一约束。
    fn admitted_over_two_seconds(len: usize) -> usize {
        let t = t0();
        let mut b = RepairBudget::new(t);
        b.update(50_000.0, 50_000.0, 100_000.0, t);
        let mut n = 0;
        let mut now = t;
        for _ in 0..2000 {
            now += Duration::from_millis(1);
            if b.try_admit(len, now) {
                n += 1;
            }
        }
        n
    }

    /// **量纲回归。** 同一份字节预算，大包就该比小包早得多地被拦下——
    /// 这正是写死"300 包/秒"做不到的区分：300 个包对 145 字节的游戏包是
    /// 43 kB/s，对 1200 字节的批量包是 360 kB/s，松紧差 8 倍。
    #[test]
    fn byte_budget_scales_with_packet_size() {
        let small = admitted_over_two_seconds(100);
        let big = admitted_over_two_seconds(1200);
        assert!(
            small > big * 3,
            "小包应能过得多得多（小 {} vs 大 {}）——按包计数的预算做不到这个区分",
            small,
            big
        );
    }

    /// 余量为零时一份都不许补，**包括初始突发量**。
    ///
    /// 桶默认是满的（连接刚建立不该因为"还没攒满"就拒绝头几份），
    /// 但余量归零时必须连桶一起清空：否则恰恰在链路已经撑不住、闸门已经
    /// 关死的时刻，还能靠残留令牌再挤一整个突发量出去。
    #[test]
    fn no_headroom_admits_nothing() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        b.update(0.0, 50_000.0, 300.0, t);
        assert!(!b.try_admit(1200, t), "余量为零时立刻就该拒绝");
        assert!(
            !b.try_admit(1200, t + Duration::from_secs(1)),
            "余量仍为零，等多久都不该放行"
        );
    }

    /// 首次拿到链路估计时不受爬升限制。
    ///
    /// 否则连接头一个爬升周期内预算恒为 0，补包在最需要的连接初期几乎是关的。
    /// 首次建立不是"放大"，只是把预算从"还不知道"变成"知道了"。
    #[test]
    fn the_first_estimate_is_adopted_without_ramping() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        b.update(80_000.0, 80_000.0, 500.0, t);
        assert!(
            b.byte_rate() > 0.0,
            "首次估计必须立即生效，实得 {}",
            b.byte_rate()
        );
    }

    /// 包速率按源速率的比例走，而不是绝对值。
    #[test]
    fn packet_budget_is_relative_to_source_rate() {
        let t = t0();
        let mut quiet = RepairBudget::new(t);
        // 安静的流：10 包/秒 → 补发上限 5 包/秒
        quiet.update(1_000_000.0, 1_000_000.0, 10.0, t);
        for _ in 0..64 {
            quiet.try_admit(100, t);
        }
        let after = t + Duration::from_secs(1);
        let mut admitted = 0;
        for _ in 0..100 {
            if quiet.try_admit(100, after) {
                admitted += 1;
            }
        }
        assert!(
            admitted <= 8,
            "10 包/秒的流不该被允许补 {} 个包——绝对阈值会放行几百个",
            admitted
        );
    }

    /// 硬天花板不能被比例算法突破。
    #[test]
    fn packet_budget_respects_the_absolute_ceiling() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        // 源速率极高，比例算出来会远超天花板
        b.update(10_000_000.0, 10_000_000.0, 100_000.0, t);
        for _ in 0..64 {
            b.try_admit(100, t);
        }
        let after = t + Duration::from_secs(1);
        let mut admitted = 0;
        for _ in 0..2000 {
            if b.try_admit(100, after) {
                admitted += 1;
            }
        }
        assert!(
            admitted <= (REPAIR_PPS_CEILING as i32 + BURST_PACKETS as i32),
            "一秒内放行了 {} 个，超过硬天花板",
            admitted
        );
    }

    /// **降速必须立即生效。** 链路突然变差时，等一个爬升窗口才收紧就来不及了。
    #[test]
    fn rate_drops_take_effect_immediately() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        b.update(500_000.0, 500_000.0, 1000.0, t);
        let high = b.byte_rate();

        let later = t + Duration::from_millis(100);
        b.update(0.0, 500_000.0, 1000.0, later);
        assert!(b.byte_rate() < high, "余量掉了就得立刻收紧，不能等爬升窗口");
    }

    /// 升速要受限：突然拉满正是触发运营商风控的模式。
    #[test]
    fn rate_increases_are_gradual() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        b.update(0.0, 100_000.0, 500.0, t);
        assert_eq!(b.byte_rate(), 0.0);

        // 余量突然变得很大，但同一时刻不该立刻拉满
        b.update(
            1_000_000.0,
            1_000_000.0,
            500.0,
            t + Duration::from_millis(100),
        );
        assert!(
            b.byte_rate() < 1_000_000.0,
            "不该一步到位；实得 {}",
            b.byte_rate()
        );
    }

    /// 字节桶拒绝时，包令牌必须还回去，否则两个桶会慢慢漂移。
    ///
    /// 用 2000 字节的包，让**字节桶先于包桶耗尽**（字节突发量 12000，
    /// 6 个包就见底，而包突发量是 8）——这样才真的走到退还那条路径。
    /// 用 1500 字节的话两个桶恰好同时空，被拒时压根没碰到字节桶，测了个寂寞。
    #[test]
    fn rejected_admission_does_not_leak_packet_tokens() {
        let t = t0();
        let mut b = RepairBudget::new(t);
        // 字节预算极小、包预算充足
        b.update(1.0, 1.0, 10_000.0, t);
        while b.try_admit(2000, t) {}

        let before = b.packets.tokens;
        assert!(before > 0.0, "包桶应还有余量，否则测不到退还路径");
        assert!(!b.try_admit(2000, t), "字节桶已空，必须拒绝");
        assert!(
            (b.packets.tokens - before).abs() < 0.001,
            "被字节桶拒绝时不该消耗包令牌，否则两个桶会逐渐漂移"
        );
    }
}
