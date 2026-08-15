//! 效果反馈闭环：回答"补包到底有没有用"。
//!
//! # 这是整套机制里唯一真正缺失的东西
//!
//! 在这之前，补包机制从来没有测量过自己的效果。它按丢包率查表决定补几份，
//! 然后就不管了——**从不检查加了冗余之后丢包有没有真的降下来**。
//! 开环加正增益，结果必然发散：补得越多 → 挤掉越多原包 → 测到的丢包越高 →
//! 查表说该补更多。实测崩溃就是这么来的。
//!
//! 闭环需要两个数，而接收端本来就同时拥有它们：
//!
//! | 量 | 含义 | 怎么得到 |
//! |---|---|---|
//! | `q` | **单次传输**丢包率 —— 发上线的每个数据报有多大概率没到 | `1 - 到达数/发送数` |
//! | `p_res` | **残余**丢包率 —— 补完之后仍然彻底丢掉的包 | `1 - 首见计数器数/序号跨度` |
//!
//! 关键在于区分"到达"和"首次见到"：一个包发了 3 份、到了 2 份，
//! 贡献 2 次**到达**但只有 1 次**首见**。于是：
//!
//! * `q` 反映链路本身有多差 —— 这才是该喂给分档表的数
//! * `p_res` 反映用户实际体验到的丢包 —— 这是要优化的目标
//! * `k_eff = 到达数/首见数 - 1` 是**实际送达**的副本数，
//!   跟我们**打算**补的份数一比，就知道副本是不是也在被一起丢
//!
//! 理论上 `p_res ≈ q^(k+1)`。实测偏离这个关系，就说明副本和原包是**一起**丢的
//! （突发丢包），补包对这条链路无效——那正是该停手的信号。
//!
//! # 为什么必须新开一个心跳标签
//!
//! `decode_heartbeat` 对长度是硬校验（`!= 11` 直接判为格式错误）。往旧标签上
//! 追加字段会让混版本之间**静默失效**：对端记一条"收到格式错误的心跳"，
//! 然后基线永远冻结在初值。所以新增 `CTRL_HEARTBEAT_V2`，过渡期两个都发，
//! 收到对端 V2 之后才停发 V1。

use std::time::{Duration, Instant};

/// 一个统计周期。
///
/// 2 秒是折中：太短则样本不足（150pps 的游戏流量下 2 秒才 300 个包，
/// 分辨率约 1~2 个百分点），太长则反馈太慢。
pub const EPOCH: Duration = Duration::from_secs(2);

/// 接收端在一个周期内的观测，通过心跳 V2 回报给发送端。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReceiverReport {
    /// 本周期覆盖的计数器区间起点
    pub window_start: u64,
    /// **所有**成功解密的数据报数，含被重放窗口判为重复的副本
    pub arrivals: u32,
    /// 其中**首次见到**的计数器数
    pub first_sightings: u32,
    /// 见到的最大计数器
    pub highest: u64,
}

impl ReceiverReport {
    /// 序号跨度：这个周期里对端**应该**发过多少个计数器。
    pub fn span(&self) -> u64 {
        self.highest
            .saturating_sub(self.window_start)
            .saturating_add(1)
    }

    /// 残余丢包率（万分之一）——补完之后仍然彻底丢掉的比例。
    ///
    /// 这是**用户实际体验到**的丢包，是要优化的目标量。
    ///
    /// **一个包都没见到时返回 0，不是 100%。** 这是 `LossMeter` 早就踩过、
    /// 文档里也写明过的坑（"空闲不是丢包"）：本端观测不到任何序号时，
    /// 无法区分"对端根本没发"和"发了但全丢了"，报 100% 会让玩家一站着不动、
    /// 一开菜单就刷满假丢包，还会把档位顶到最高。尾部全丢那种真实场景由
    /// 心跳携带的 `highest` 另行覆盖（见《抗丢包方案设计》4.6 节），
    /// 不该在这里靠猜。
    pub fn residual_loss_bp(&self) -> u16 {
        if self.first_sightings == 0 {
            return 0;
        }
        let span = self.span();
        if span == 0 {
            return 0;
        }
        let seen = (self.first_sightings as u64).min(span);
        (((span - seen).saturating_mul(10_000)) / span).min(10_000) as u16
    }

    /// 实际送达的副本数：`到达数/首见数 - 1`。
    ///
    /// 跟我们**打算**补的份数对比：明显偏低就说明副本跟原包一起被丢了
    /// （典型的突发丢包），补包对这条链路无效。
    pub fn effective_copies(&self) -> f32 {
        if self.first_sightings == 0 {
            return 0.0;
        }
        self.arrivals as f32 / self.first_sightings as f32 - 1.0
    }

    /// 单次传输丢包率（万分之一）：发上线的每个数据报有多大概率没到。
    ///
    /// **这才是该喂给分档表的数**，不是残余丢包率。残余丢包率已经被我们自己的
    /// 补包"修饰"过了，拿它去决定补几份就是拿结果当原因。
    pub fn per_transmission_loss_bp(&self, transmissions: u64) -> u16 {
        if transmissions == 0 {
            return 0;
        }
        let arrived = (self.arrivals as u64).min(transmissions);
        (((transmissions - arrived).saturating_mul(10_000)) / transmissions).min(10_000) as u16
    }
}

/// 发送端按周期累计的发送量，用来跟接收端的报告对账。
#[derive(Clone, Copy, Debug, Default)]
pub struct SenderEpoch {
    /// 本周期实际交给 `send_datagram` 的数据报总数（原包 + 副本 + 重传）
    pub transmissions: u64,
    /// 其中消耗掉的计数器数（即原包数）
    pub counters_used: u64,
    /// 本周期生效的补发档位
    pub tier: u8,
}

/// 反事实 A/B 的阶段。
///
/// 光有 `p_res` 还不能说明"补 2 份比补 1 份好"——那只是在跟一个**模型**
/// （`q^(k+1)`）比，而模型假设各份独立，恰恰是突发丢包会违反的前提。
/// 唯一诚实的办法是真的去跑一个少补一份的周期，直接比。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbPhase {
    /// 正常运行，用当前档位
    Normal,
    /// 对照周期，降一档
    Counterfactual,
}

/// 效果不足的判定阈值：降一档之后残余丢包**没有明显变差**，
/// 就说明多出来的那一份没有挣到它占用的带宽。
const MIN_BENEFIT: f32 = 0.30;
/// 代价阈值：多补一份换来的排队延迟增长超过这个比例就不值。
const MAX_COST: f32 = 0.10;
/// 判定"没效果"之后锁定多久不再上调。
const LOCKOUT: Duration = Duration::from_secs(30);

/// 效果评估器。纯逻辑，时间由调用方传入。
pub struct EffectMeter {
    phase: AbPhase,
    epochs_in_phase: u32,
    /// 正常周期最近一次的残余丢包与梯度
    normal_res_bp: Option<u16>,
    normal_gradient: f32,
    /// 因为"补包没效果"而施加的档位上限；`None` 表示不限制
    cap: Option<u8>,
    cap_until: Option<Instant>,
}

/// 每跑几个正常周期插入一个对照周期。
///
/// 4 表示 1/4 的时间在少补一份。代价是那个周期保护稍弱（ARQ 仍然覆盖），
/// 换来的是**唯一**能证明补包有没有用的证据。
const NORMAL_EPOCHS_PER_COUNTERFACTUAL: u32 = 3;

impl EffectMeter {
    pub fn new() -> Self {
        Self {
            phase: AbPhase::Normal,
            epochs_in_phase: 0,
            normal_res_bp: None,
            normal_gradient: 0.0,
            cap: None,
            cap_until: None,
        }
    }

    pub fn phase(&self) -> AbPhase {
        self.phase
    }

    /// 当前施加的档位上限（`None` 表示不限）。
    pub fn tier_cap(&self, now: Instant) -> Option<u8> {
        match (self.cap, self.cap_until) {
            (Some(c), Some(until)) if now < until => Some(c),
            _ => None,
        }
    }

    /// 一个周期结束时调用，传入这个周期的观测。
    ///
    /// `gradient` 是本周期的平均排队延迟梯度，用来衡量"多补一份的代价"。
    pub fn on_epoch_end(&mut self, report: &ReceiverReport, tier: u8, gradient: f32, now: Instant) {
        let res = report.residual_loss_bp();

        match self.phase {
            AbPhase::Normal => {
                self.normal_res_bp = Some(res);
                self.normal_gradient = gradient;
                self.epochs_in_phase += 1;
                if self.epochs_in_phase >= NORMAL_EPOCHS_PER_COUNTERFACTUAL && tier > 0 {
                    // 只有真的在补包时才值得做对照——tier 已经是 0 就没什么可降的
                    self.phase = AbPhase::Counterfactual;
                    self.epochs_in_phase = 0;
                }
            }
            AbPhase::Counterfactual => {
                // 对照周期跑完，跟最近的正常周期比
                if let Some(normal) = self.normal_res_bp {
                    let benefit = if normal == 0 && res == 0 {
                        // 两边都是 0：补包没有可证明的收益
                        0.0
                    } else {
                        (res as f32 - normal as f32) / (res.max(1) as f32)
                    };
                    let cost = self.normal_gradient - gradient;

                    if benefit < MIN_BENEFIT || cost > MAX_COST {
                        // 多补的那一份没挣到自己的带宽：压一档，锁定一段时间。
                        //
                        // **这个规则只允许往下压，永远不用来往上加。** 在游戏流量的
                        // 包速率下，2 秒周期只有几百个样本，分辨率大约 1~2 个百分点，
                        // 拿这种精度的读数去证明"该多补"是不负责任的；
                        // 但用它证明"补了没用"是安全的方向。
                        self.cap = Some(tier.saturating_sub(1));
                        self.cap_until = Some(now + LOCKOUT);
                    }
                }
                self.phase = AbPhase::Normal;
                self.epochs_in_phase = 0;
            }
        }
    }

    /// 这个周期实际该用的档位（已应用对照与上限）。
    pub fn effective_tier(&self, proposed: u8, now: Instant) -> u8 {
        let after_cap = match self.tier_cap(now) {
            Some(c) => proposed.min(c),
            None => proposed,
        };
        match self.phase {
            AbPhase::Normal => after_cap,
            AbPhase::Counterfactual => after_cap.saturating_sub(1),
        }
    }
}

impl Default for EffectMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(span_start: u64, highest: u64, arrivals: u32, first: u32) -> ReceiverReport {
        ReceiverReport {
            window_start: span_start,
            highest,
            arrivals,
            first_sightings: first,
        }
    }

    /// 残余丢包只看首见数，跟到达多少副本无关。
    #[test]
    fn residual_loss_counts_unique_counters_only() {
        // 跨度 100，首见 90 → 残余 10%
        let r = report(0, 99, 270, 90);
        assert_eq!(r.residual_loss_bp(), 1000);
    }

    /// **`p_res` 和 `q` 必须能分开。**
    ///
    /// 同一批数据：单次传输丢了三分之一，但因为补了 2 份，用户实际一个都没丢。
    /// 只看其中一个数会得出完全相反的结论——这正是为什么两个都要测。
    #[test]
    fn per_transmission_and_residual_loss_are_different_things() {
        // 100 个计数器各发 3 份 = 300 次传输，到了 200 次，但 100 个计数器全都
        // 至少到了一份
        let r = report(0, 99, 200, 100);
        assert_eq!(r.residual_loss_bp(), 0, "用户视角：一个包都没丢");
        assert_eq!(
            r.per_transmission_loss_bp(300),
            3333,
            "链路视角：单次传输丢了三分之一"
        );
    }

    /// 实际送达的副本数能反映"副本是不是跟原包一起被丢了"。
    #[test]
    fn effective_copies_reveals_correlated_loss() {
        // 补 2 份、全都到了：每个计数器到 3 次
        let good = report(0, 99, 300, 100);
        assert!((good.effective_copies() - 2.0).abs() < 0.01);

        // 补 2 份、但突发丢包把副本和原包一起吞了：几乎没有多余的到达
        let bursty = report(0, 99, 105, 100);
        assert!(
            bursty.effective_copies() < 0.1,
            "副本没送达时必须能看出来，实得 {}",
            bursty.effective_copies()
        );
    }

    /// **空闲不是丢包。**
    ///
    /// 一个包都没见到时无法区分"对端没发"和"全丢了"，报 100% 会让玩家
    /// 站着不动就刷满假丢包、把档位顶到最高。`LossMeter` 早就踩过这个坑，
    /// 这里是同一个陷阱的另一处入口。
    #[test]
    fn empty_report_is_not_total_loss() {
        let r = ReceiverReport::default();
        assert_eq!(r.residual_loss_bp(), 0, "没有观测 ≠ 全丢");
        assert_eq!(r.per_transmission_loss_bp(0), 0);
        assert_eq!(r.effective_copies(), 0.0);

        // 有跨度但一个都没首见，同样不能报 100%
        let silent = ReceiverReport {
            window_start: 100,
            highest: 200,
            arrivals: 0,
            first_sightings: 0,
        };
        assert_eq!(silent.residual_loss_bp(), 0, "没有观测 ≠ 全丢");
    }

    /// 补包确实有效时，不该被压档。
    #[test]
    fn effective_redundancy_is_not_capped() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        // 三个正常周期：残余丢包很低
        for _ in 0..3 {
            m.on_epoch_end(&report(0, 99, 300, 100), 2, 0.05, t);
        }
        assert_eq!(m.phase(), AbPhase::Counterfactual, "该进对照周期了");
        // 对照周期少补一份，残余丢包明显变差 → 说明那一份是有用的
        m.on_epoch_end(&report(0, 99, 190, 80), 1, 0.05, t + EPOCH);
        assert_eq!(m.tier_cap(t + EPOCH), None, "补包有效时不该压档");
    }

    /// **补包没效果时必须自动压档。** 这是整个闭环存在的意义。
    #[test]
    fn ineffective_redundancy_gets_capped() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        for _ in 0..3 {
            m.on_epoch_end(&report(0, 99, 300, 90), 2, 0.05, t);
        }
        // 对照周期少补一份，残余丢包**没有变差** → 那一份纯属浪费带宽
        m.on_epoch_end(&report(0, 99, 190, 90), 2, 0.05, t + EPOCH);
        assert_eq!(m.tier_cap(t + EPOCH), Some(1), "补了没用就该压档");
    }

    /// 代价过高（延迟涨了）时也要压档，即使残余丢包看起来好了一点。
    #[test]
    fn redundancy_that_costs_too_much_latency_gets_capped() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        for _ in 0..3 {
            // 正常周期梯度很高
            m.on_epoch_end(&report(0, 99, 300, 95), 2, 0.50, t);
        }
        // 对照周期梯度低得多 → 说明那一份副本在制造排队延迟
        m.on_epoch_end(&report(0, 99, 190, 90), 2, 0.05, t + EPOCH);
        assert_eq!(m.tier_cap(t + EPOCH), Some(1), "代价过高也要压档");
    }

    /// 压档要能过期，链路变好之后不能被永久摁住。
    #[test]
    fn the_cap_expires() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        for _ in 0..3 {
            m.on_epoch_end(&report(0, 99, 300, 90), 2, 0.05, t);
        }
        m.on_epoch_end(&report(0, 99, 190, 90), 2, 0.05, t + EPOCH);
        assert!(m.tier_cap(t + EPOCH).is_some());
        assert_eq!(
            m.tier_cap(t + EPOCH + LOCKOUT + Duration::from_secs(1)),
            None,
            "锁定期过后必须解除，否则链路恢复了也补不回来"
        );
    }

    /// 对照周期本身要真的降一档，否则测了个寂寞。
    #[test]
    fn the_counterfactual_epoch_actually_lowers_the_tier() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        for _ in 0..3 {
            m.on_epoch_end(&report(0, 99, 300, 100), 2, 0.05, t);
        }
        assert_eq!(m.phase(), AbPhase::Counterfactual);
        assert_eq!(m.effective_tier(2, t), 1, "对照周期必须少补一份");
    }

    /// tier 已经是 0 时不该进对照周期——没什么可降的。
    #[test]
    fn no_counterfactual_when_not_repairing() {
        let t = Instant::now();
        let mut m = EffectMeter::new();
        for _ in 0..5 {
            m.on_epoch_end(&report(0, 99, 100, 100), 0, 0.0, t);
        }
        assert_eq!(m.phase(), AbPhase::Normal, "没在补包就不用做对照");
    }
}
