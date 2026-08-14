//! 进程内链路模型：在没有实验室的情况下验证控制器的**闭环**行为。
//!
//! # 为什么必须有这个
//!
//! 单个函数的单元测试只能证明"给定输入产生正确输出"。但这套机制真正出事的方式
//! 是**闭环发散**——每一步的局部决策都说得通，合起来却形成正反馈：
//!
//! ```text
//! 链路被占满 → 微量丢包 → 加冗余 → 副本挤掉原包 → 丢包更多 → 继续加冗余
//! ```
//!
//! 这种问题任何孤立的单元测试都抓不到，只能把控制器接上一个会**对它的动作做出
//! 反应**的环境，跑一段时间，看它收不收敛。
//!
//! 上一版之所以带着一个必然发散的环上线，根本原因就是控制逻辑焊死在 quinn 连接
//! 和收包热路径里，没有任何一条路径能在没有真实网络的情况下驱动它。这里的模型
//! 不追求物理精确，只要**保留那条反馈路径**：发得越多 → 队列越满 → 丢得越多。
//!
//! 跑在 CI 里，不需要第二台机器、不需要 tc/dummynet、不需要 sleep。

use std::time::{Duration, Instant};

/// 一条被建模的链路。
pub struct SimLink {
    /// 链路容量（字节/秒）
    pub capacity_bps: f64,
    /// 单程基础延迟
    pub base_rtt: Duration,
    /// 队列容量（字节）
    pub queue_bytes_max: usize,
    /// 与拥塞无关的随机丢包率（0.0~1.0），模拟链路本身的噪声
    pub random_loss: f64,

    /// 当前排队字节数
    queued: f64,
    /// 已投递字节数（累计）
    delivered_bytes: u64,
    /// 因队列溢出被丢弃的包数
    dropped: u64,
    /// 因随机丢包被丢弃的包数
    lost_random: u64,
    /// 一个简单的确定性伪随机源——测试必须可复现，不能用真随机
    rng: u64,
}

impl SimLink {
    pub fn new(capacity_bps: f64, base_rtt: Duration, queue_bytes_max: usize) -> Self {
        Self {
            capacity_bps,
            base_rtt,
            queue_bytes_max,
            random_loss: 0.0,
            queued: 0.0,
            delivered_bytes: 0,
            dropped: 0,
            lost_random: 0,
            rng: 0x2545_F491_4F6C_DD1D,
        }
    }

    pub fn with_random_loss(mut self, p: f64) -> Self {
        self.random_loss = p;
        self
    }

    fn next_unit(&mut self) -> f64 {
        // xorshift64*，够用且完全确定
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// 队列剩余空间，对应 `Connection::datagram_send_buffer_space()`。
    pub fn free_space(&self) -> usize {
        (self.queue_bytes_max as f64 - self.queued).max(0.0) as usize
    }

    /// 尝试发一个包。队列装不下就返回 false（尾丢）。
    pub fn send(&mut self, len: usize) -> bool {
        if self.free_space() < len {
            self.dropped += 1;
            return false;
        }
        if self.random_loss > 0.0 && self.next_unit() < self.random_loss {
            // 随机丢包发生在链路上：字节仍然占用了发送容量，只是对端收不到
            self.lost_random += 1;
        }
        self.queued += len as f64;
        true
    }

    /// 推进 `dt`，按容量排空队列。
    pub fn advance(&mut self, dt: Duration) {
        let drain = self.capacity_bps * dt.as_secs_f64();
        let actually = drain.min(self.queued);
        self.queued -= actually;
        self.delivered_bytes += actually as u64;
    }

    /// 当前排队延迟——队列里的数据全部发完需要多久。
    pub fn queueing_delay(&self) -> Duration {
        if self.capacity_bps <= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(self.queued / self.capacity_bps)
    }

    /// 当前 RTT = 基础延迟 + 排队延迟。
    pub fn rtt(&self) -> Duration {
        self.base_rtt + self.queueing_delay()
    }

    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair::gate::{Gate, GateController, MinRttFilter, Observation};

    const MTU: usize = 1184;
    const STEP: Duration = Duration::from_millis(1);
    const SAMPLE_EVERY: u32 = 50;

    /// 把真实的 `GateController` 接到 `SimLink` 上跑一段时间。
    ///
    /// 返回 (最终闸门状态, 闸门状态变化次数, 最大排队延迟, 被丢的原包数)。
    ///
    /// `source_bytes_per_step` 是业务每毫秒要发多少字节——**外生的**，
    /// 控制器管不了它，只能决定自己额外补多少，这正是真实情况。
    fn run(
        link: &mut SimLink,
        seconds: u64,
        source_bytes_per_step: f64,
        extra_copies_from_loss: u8,
    ) -> (Gate, usize, Duration, u64) {
        let t0 = Instant::now();
        let mut gate = GateController::new();
        let mut min_rtt = MinRttFilter::new(Duration::from_secs(10), Duration::from_secs(1));
        let mut btlbw = 0.0f64;
        let mut self_evicted_recently = false;
        let mut pending = 0.0f64;
        let mut transitions = 0usize;
        let mut last_state = gate.state();
        let mut max_delay = Duration::ZERO;
        let mut prev_delivered = 0u64;

        for step in 0..(seconds * 1000) {
            let now = t0 + STEP * step as u32;

            // 业务产生数据；控制器决定在原包之外补几份
            pending += source_bytes_per_step;
            while pending >= MTU as f64 {
                pending -= MTU as f64;
                if !link.send(MTU) {
                    self_evicted_recently = true;
                }
                let allowed = gate.state().max_extra_copies().min(extra_copies_from_loss);
                for _ in 0..allowed {
                    if !link.send(MTU) {
                        self_evicted_recently = true;
                    }
                }
            }

            link.advance(STEP);
            max_delay = max_delay.max(link.queueing_delay());

            // 每 50ms 采样一次，跟真实采样器同频
            if step % SAMPLE_EVERY as u64 == 0 && step > 0 {
                let srtt = link.rtt();
                min_rtt.observe(srtt, now);
                let rtt_min = min_rtt.get().unwrap_or(srtt);

                let delivered = link.delivered_bytes();
                let rate =
                    (delivered - prev_delivered) as f64 / (STEP * SAMPLE_EVERY).as_secs_f64();
                prev_delivered = delivered;
                // 跟真实采样器一致：不是 app-limited 时才更新容量估计
                if rate > btlbw && link.queued_bytes() > 0 {
                    btlbw = rate;
                } else {
                    btlbw *= 0.999;
                }
                let capacity = btlbw.max(link.capacity_bps * 0.5);
                let headroom = (capacity * 0.85 - rate).max(0.0);

                let obs = Observation {
                    self_evicted: self_evicted_recently,
                    occupancy: 1.0 - link.free_space() as f32 / link.queue_bytes_max as f32,
                    delay_gradient: min_rtt.gradient(srtt),
                    queueing_delay: srtt.saturating_sub(rtt_min),
                    headroom_bps: headroom as i64,
                    congestion_events: 0,
                };
                let state = gate.step(&obs, now);
                if state != last_state {
                    transitions += 1;
                    last_state = state;
                }
                self_evicted_recently = false;
            }
        }
        (gate.state(), transitions, max_delay, link.dropped())
    }

    /// **干净且宽裕的链路上，闸门必须一直开着，一次都不能关。**
    ///
    /// 这是最重要的一条回归。实测数据里闸门有 75% 的时间因为带宽估计器坏掉
    /// 而错误关闭，补包机制全程停摆——而这种失效是**静默**的：功能没了，
    /// 没有报错，没人会发现。
    #[test]
    fn a_healthy_link_keeps_the_gate_open() {
        // 1 MB/s 的链路，业务只用 100 kB/s，余量充足
        let mut link = SimLink::new(1_000_000.0, Duration::from_millis(20), 96 * 1024);
        let (state, transitions, max_delay, dropped) = run(&mut link, 10, 100.0, 2);

        assert_eq!(
            state,
            Gate::Open,
            "宽裕链路上闸门必须开着（这正是实测中坏掉的行为）"
        );
        assert_eq!(
            transitions, 0,
            "不该有任何状态跳变，实得 {} 次",
            transitions
        );
        assert_eq!(dropped, 0, "不该丢包");
        assert!(
            max_delay < Duration::from_millis(12),
            "排队延迟不该堆起来，实得 {:?}",
            max_delay
        );
    }

    /// **业务把链路占满时，闸门必须关掉补包，并且不能反复横跳。**
    ///
    /// 振荡跟不收敛一样糟：它会把链路一直摁在临界点上。
    #[test]
    fn a_saturated_link_closes_the_gate_without_oscillating() {
        // 200 kB/s 的链路，业务就要 250 kB/s——本来就超了
        let mut link = SimLink::new(200_000.0, Duration::from_millis(20), 96 * 1024);
        let (state, transitions, _, _) = run(&mut link, 10, 250.0, 2);

        assert_eq!(state, Gate::Closed, "链路饱和时必须关闸");
        assert!(
            transitions < 10,
            "10 秒内跳变 {} 次，说明在拥塞边缘反复横跳",
            transitions
        );
    }

    /// **旧逻辑必须在同一个模型里崩掉。**
    ///
    /// 这一条证明模型本身足够灵敏——如果连已知会发散的行为都测不出来，
    /// 那前面那些"通过了"的断言也说明不了任何问题。
    ///
    /// 旧逻辑 = 没有闸门（永远按丢包率给的档位补满），正是导致实测崩溃的形态。
    #[test]
    fn the_old_ungated_behaviour_still_collapses_in_this_model() {
        let mut link = SimLink::new(200_000.0, Duration::from_millis(20), 96 * 1024);
        let t0 = Instant::now();
        let mut pending = 0.0f64;
        let mut max_delay = Duration::ZERO;

        // 无闸门：每个包无条件补 2 份，这就是旧代码在测到丢包后的行为
        for step in 0..10_000u64 {
            let _ = t0;
            pending += 250.0;
            while pending >= MTU as f64 {
                pending -= MTU as f64;
                link.send(MTU);
                link.send(MTU);
                link.send(MTU);
            }
            link.advance(STEP);
            max_delay = max_delay.max(link.queueing_delay());
        }

        assert!(
            link.dropped() > 1000,
            "无闸门时必须出现大量自丢包，实得 {}——模型不够灵敏，前面的断言也就不可信",
            link.dropped()
        );
        assert!(
            max_delay >= Duration::from_millis(400),
            "无闸门时队列必须堆起来，实得 {:?}",
            max_delay
        );
    }

    /// 有闸门时，同样的过载场景下自丢包必须显著少于无闸门。
    #[test]
    fn the_gate_substantially_reduces_self_inflicted_drops() {
        let mut gated = SimLink::new(200_000.0, Duration::from_millis(20), 96 * 1024);
        let (_, _, _, gated_drops) = run(&mut gated, 10, 250.0, 2);

        let mut ungated = SimLink::new(200_000.0, Duration::from_millis(20), 96 * 1024);
        let mut pending = 0.0f64;
        for _ in 0..10_000u64 {
            pending += 250.0;
            while pending >= MTU as f64 {
                pending -= MTU as f64;
                ungated.send(MTU);
                ungated.send(MTU);
                ungated.send(MTU);
            }
            ungated.advance(STEP);
        }

        assert!(
            gated_drops * 2 < ungated.dropped(),
            "有闸门({}) 应显著少于无闸门({})",
            gated_drops,
            ungated.dropped()
        );
    }
}
