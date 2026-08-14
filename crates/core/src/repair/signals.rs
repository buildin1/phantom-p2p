//! 链路信号采样：把 quinn 的连接状态翻译成闸门看得懂的 [`Observation`]。
//!
//! # 为什么单独开一个采样任务，而不是在发包时顺手读
//!
//! `Connection::stats()` 和 `datagram_send_buffer_space()` 都要取连接状态锁。
//! 联机跑图时一秒上千个包，逐包去取这把锁就是把控制逻辑焊进转发热路径——
//! 这个项目已经因为同类问题吃过一次亏（`tx-orig` 曾经每包同步写一次日志，
//! 是"大量发包时 ping 从 40ms 飙到 1300ms"的真正原因）。
//!
//! 所以采样固定 20Hz（50ms）在独立任务里做，结果写进原子量；热路径只读原子量，
//! 无锁、无系统调用。50ms 对被控对象（队列堆积，几十毫秒尺度）足够快，
//! 对比上一版**每秒一次、且只在收到心跳时才算**的拥塞判定，快了一个数量级。
//!
//! # 唯一的例外：自挤占检测
//!
//! "这次发送会不会挤掉队列里更旧的包"必须逐包判断，不能等 50ms 后的采样——
//! 等到那时包已经发出去、原包已经被挤掉了。所以那一条留在
//! `tun_bridge.rs` 的发送路径上直接读 `datagram_send_buffer_space()`，
//! 采样器这边只负责把"最近有没有发生过自挤占"汇总给闸门。

use super::budget::RepairBudget;
use super::gate::{Gate, GateController, MinRttFilter, Observation, TripReason};
use quinn::Connection;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant};

/// 采样周期。
const SAMPLE_INTERVAL: Duration = Duration::from_millis(50);
/// 最小 RTT 的观测窗口与分桶粒度，见 [`MinRttFilter`]。
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
const MIN_RTT_BUCKET: Duration = Duration::from_secs(1);
/// 自挤占信号的保持时间：这段时间内发生过一次就算"最近有"。
///
/// 比采样周期长几倍，避免一次自挤占正好落在两次采样之间被漏掉。
const SELF_EVICT_MEMORY: Duration = Duration::from_millis(200);
/// 计算可用带宽时给链路留的安全边际。
///
/// 不留边际的话，估计带宽本身的误差就足以让我们把链路刚好压到临界点。
const HEADROOM_SAFETY: f64 = 0.85;

/// 供热路径无锁读取的链路状态。
///
/// 每条对端连接一份。写入方是 20Hz 的采样任务，读取方是转发热路径。
pub struct LinkSignals {
    /// 当前闸门档位，见 [`Gate`]。用 u8 存是为了热路径一次原子读就拿到。
    gate: AtomicU8,
    /// 关闸原因，仅供日志。
    reason: AtomicU8,
    /// 最近一次发送因队列没空间而被放弃的时刻（相对 `origin` 的毫秒数）。
    /// 0 表示从未发生。
    last_self_evict_ms: AtomicU64,
    /// 计时原点：`Instant` 不能塞进原子量，用相对毫秒数代替。
    origin: Instant,
    /// 采样任务是否还活着。连接关闭后置 false，避免重复启动。
    running: AtomicBool,

    /// 业务原包的累计字节数与包数（**只算原包，不含补发**）。
    ///
    /// 采样器做差算出源速率，预算桶按它的比例定上限。必须只算原包：
    /// 把补发也算进"源速率"会形成自我强化的循环——补得越多，算出来的
    /// 源速率越高，允许补的量又跟着涨。
    source_bytes: AtomicU64,
    source_pkts: AtomicU64,

    /// 补发预算，见 [`RepairBudget`]。
    ///
    /// 写入方是采样器（每 50ms 更新速率），读取方是发送路径（每份补发申请一次）。
    /// 用同步锁而不是原子量，是因为令牌桶是有状态的多字段结构，没法拆成独立原子量。
    /// 只在**要发补发包时**才会取这把锁，干净链路上根本不会走到。
    budget: SyncMutex<RepairBudget>,

    // ── 以下仅供日志与诊断，不参与决策 ────────────────────────────
    occupancy_pct: AtomicU8,
    gradient_pct: AtomicU8,
    srtt_ms: AtomicU64,
    min_rtt_ms: AtomicU64,
    cwnd_bytes: AtomicU64,
    headroom_bps: AtomicU64,
}

impl LinkSignals {
    pub fn new() -> Self {
        Self {
            // 从 Open 起步：不预设链路有问题。
            gate: AtomicU8::new(Gate::Open as u8),
            reason: AtomicU8::new(0),
            last_self_evict_ms: AtomicU64::new(0),
            origin: Instant::now(),
            running: AtomicBool::new(false),
            source_bytes: AtomicU64::new(0),
            source_pkts: AtomicU64::new(0),
            budget: SyncMutex::new(RepairBudget::new(Instant::now())),
            occupancy_pct: AtomicU8::new(0),
            gradient_pct: AtomicU8::new(0),
            srtt_ms: AtomicU64::new(0),
            min_rtt_ms: AtomicU64::new(0),
            cwnd_bytes: AtomicU64::new(0),
            headroom_bps: AtomicU64::new(0),
        }
    }

    /// 热路径读：这一刻最多允许补几份。
    pub fn max_extra_copies(&self) -> u8 {
        self.gate_state().max_extra_copies()
    }

    pub fn gate_state(&self) -> Gate {
        match self.gate.load(Ordering::Relaxed) {
            0 => Gate::Closed,
            1 => Gate::Throttled,
            _ => Gate::Open,
        }
    }

    /// 发送路径发现"队列没空间、这次发送会挤掉更旧的包"时调用。
    ///
    /// 这是整套信号里**唯一不需要推断的**：它被调用就直接证明我们自己是丢包
    /// 来源，不用比阈值、不用等对端回话。
    pub fn note_self_evict(&self) {
        let ms = self.origin.elapsed().as_millis() as u64;
        // 存 ms+1，把 0 保留给"从未发生"
        self.last_self_evict_ms.store(ms + 1, Ordering::Relaxed);
    }

    /// 发送路径每发出一个**原包**时调用，用于估计源速率。
    ///
    /// 补发包绝不能算进来：那会形成自我强化的循环（补得越多 → 算出的源速率越高
    /// → 允许补的量越大）。
    pub fn note_original(&self, len: usize) {
        self.source_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.source_pkts.fetch_add(1, Ordering::Relaxed);
    }

    /// 申请发一份 `len` 字节的补发包。两个预算桶都批准才放行。
    ///
    /// 锁中毒时放行：预算是"锦上添花"的限制，不该因为它自己出问题就
    /// 把补包功能整个废掉。
    pub fn admit_repair(&self, len: usize) -> bool {
        match self.budget.lock() {
            Ok(mut b) => b.try_admit(len, Instant::now()),
            Err(_) => true,
        }
    }

    fn recent_self_evict(&self, now_ms: u64) -> bool {
        match self.last_self_evict_ms.load(Ordering::Relaxed) {
            0 => false,
            stamp => now_ms + 1 < stamp + SELF_EVICT_MEMORY.as_millis() as u64,
        }
    }

    /// 一行结构化诊断，每秒打一条。
    ///
    /// 验收标准是：**把日志交给一个没读过代码的人，他应该能一眼说出上次掉线
    /// 是自挤占还是链路丢包。** 旧日志里那条 `[TUN] 入方向丢包 x.xx%` 对两种
    /// 成因都兼容，这正是最近几次排查都要来回好几轮的原因。
    pub fn diagnostic_line(&self) -> String {
        format!(
            "gate={} reason={} occ={:.2} grad={:.2} srtt={}ms rttmin={}ms cwnd={}B headroom={}B/s",
            self.gate_state().as_str(),
            self.reason_str(),
            self.occupancy_pct.load(Ordering::Relaxed) as f32 / 100.0,
            self.gradient_pct.load(Ordering::Relaxed) as f32 / 100.0,
            self.srtt_ms.load(Ordering::Relaxed),
            self.min_rtt_ms.load(Ordering::Relaxed),
            self.cwnd_bytes.load(Ordering::Relaxed),
            self.headroom_bps.load(Ordering::Relaxed),
        )
    }

    fn reason_str(&self) -> &'static str {
        match self.reason.load(Ordering::Relaxed) {
            1 => TripReason::SelfEvict.as_str(),
            2 => TripReason::Occupancy.as_str(),
            3 => TripReason::DelayGradient.as_str(),
            4 => TripReason::NoHeadroom.as_str(),
            _ => TripReason::Clean.as_str(),
        }
    }

    fn store_reason(&self, r: TripReason) {
        let v = match r {
            TripReason::Clean => 0u8,
            TripReason::SelfEvict => 1,
            TripReason::Occupancy => 2,
            TripReason::DelayGradient => 3,
            TripReason::NoHeadroom => 4,
        };
        self.reason.store(v, Ordering::Relaxed);
    }
}

impl Default for LinkSignals {
    fn default() -> Self {
        Self::new()
    }
}

/// 启动这条连接的采样任务。连接关闭后自动退出。
///
/// `queue_capacity` 是 QUIC 数据报发送队列的容量（`DATAGRAM_SEND_BUFFER_BYTES`），
/// 用来把剩余空间换算成占用率。
pub fn spawn_sampler(conn: Connection, signals: Arc<LinkSignals>, queue_capacity: usize) {
    if signals.running.swap(true, Ordering::SeqCst) {
        return; // 已经有一个在跑了
    }
    tokio::spawn(async move {
        let mut gate = GateController::new();
        let mut min_rtt = MinRttFilter::new(MIN_RTT_WINDOW, MIN_RTT_BUCKET);
        // 累计计数器要做差，先记住上一次的读数
        let mut prev_tx_bytes = 0u64;
        let mut prev_congestion_events = 0u64;
        let mut prev_source_bytes = 0u64;
        let mut prev_source_pkts = 0u64;
        let mut prev_sample = Instant::now();
        // 带宽估计取窗口内最大值（BBR 的思路）：单次采样受调度抖动影响很大，
        // 而链路容量是相对稳定的，取最大值比取平均更接近真实上限。
        let mut btlbw_bps: f64 = 0.0;

        loop {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
            if conn.close_reason().is_some() {
                signals.running.store(false, Ordering::SeqCst);
                break;
            }

            let now = Instant::now();
            let elapsed = now.duration_since(prev_sample).as_secs_f64().max(0.001);
            prev_sample = now;

            let stats = conn.stats();
            let srtt = stats.path.rtt;
            min_rtt.observe(srtt, now);
            let gradient = min_rtt.gradient(srtt);

            let free = conn.datagram_send_buffer_space();
            let occupancy = if queue_capacity == 0 {
                0.0
            } else {
                1.0 - (free.min(queue_capacity) as f32 / queue_capacity as f32)
            };

            // 出方向实际投递速率。只有队列里有东西时才算数——链路空闲时这个数
            // 反映的是业务发了多少，不是链路能承载多少，拿它当容量会严重低估。
            let tx_bytes = stats.udp_tx.bytes;
            let delta_bytes = tx_bytes.saturating_sub(prev_tx_bytes);
            prev_tx_bytes = tx_bytes;
            let rate = delta_bytes as f64 / elapsed;
            if occupancy > 0.0 && rate > btlbw_bps {
                btlbw_bps = rate;
            } else {
                // 缓慢衰减，让长期没跑满的链路不会永远记着一个过时的高点
                btlbw_bps *= 0.995;
            }

            // 余量 = 估计容量 × 安全边际 − 当前业务速率。
            // 注意这里用的是**当前实际发送速率**，因为源速率对我们是外生的：
            // 没法让游戏少发包，只能决定自己额外加多少。
            let headroom = (btlbw_bps * HEADROOM_SAFETY - rate).max(0.0);

            let congestion_events = stats.path.congestion_events;
            let delta_congestion = congestion_events.saturating_sub(prev_congestion_events);
            prev_congestion_events = congestion_events;

            let now_ms = signals.origin.elapsed().as_millis() as u64;
            let obs = Observation {
                self_evicted: signals.recent_self_evict(now_ms),
                occupancy,
                delay_gradient: gradient,
                // btlbw 还没建立起来时（连接刚起、还没跑满过）不要因为
                // "算出来余量是 0"就误判成拥塞——那时根本还没有容量估计。
                headroom_bps: if btlbw_bps <= 0.0 {
                    i64::MAX
                } else {
                    headroom as i64
                },
                congestion_events: delta_congestion,
            };

            let state = gate.step(&obs, now);
            signals.gate.store(state as u8, Ordering::Relaxed);
            signals.store_reason(gate.last_reason());

            // 用实测的源速率刷新补发预算。源速率只统计原包，见 `note_original`。
            let src_bytes = signals.source_bytes.load(Ordering::Relaxed);
            let src_pkts = signals.source_pkts.load(Ordering::Relaxed);
            let source_bps = src_bytes.saturating_sub(prev_source_bytes) as f32 / elapsed as f32;
            let source_pps = src_pkts.saturating_sub(prev_source_pkts) as f32 / elapsed as f32;
            prev_source_bytes = src_bytes;
            prev_source_pkts = src_pkts;
            if let Ok(mut b) = signals.budget.lock() {
                b.update(headroom as f32, source_bps, source_pps, now);
            }

            // 诊断量
            signals.occupancy_pct.store(
                (occupancy * 100.0).clamp(0.0, 255.0) as u8,
                Ordering::Relaxed,
            );
            signals.gradient_pct.store(
                (gradient * 100.0).clamp(0.0, 255.0) as u8,
                Ordering::Relaxed,
            );
            signals
                .srtt_ms
                .store(srtt.as_millis() as u64, Ordering::Relaxed);
            signals.min_rtt_ms.store(
                min_rtt.get().map(|d| d.as_millis() as u64).unwrap_or(0),
                Ordering::Relaxed,
            );
            signals.cwnd_bytes.store(stats.path.cwnd, Ordering::Relaxed);
            signals
                .headroom_bps
                .store(headroom as u64, Ordering::Relaxed);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自挤占信号要有一小段记忆，否则一次挤占正好落在两次采样之间就被漏掉。
    #[test]
    fn self_evict_is_remembered_across_a_sampling_gap() {
        let s = LinkSignals::new();
        assert!(!s.recent_self_evict(0), "初始不该有自挤占");

        s.note_self_evict();
        let at = s.origin.elapsed().as_millis() as u64;
        assert!(s.recent_self_evict(at), "刚发生应立即可见");
        assert!(
            s.recent_self_evict(at + 100),
            "100ms 内应仍然可见（采样周期 50ms，要能跨过去）"
        );
        assert!(
            !s.recent_self_evict(at + 500),
            "500ms 后应该过期，否则一次偶发挤占会把闸门永久摁死"
        );
    }

    /// 档位映射不能错位——这是热路径每个包都要读的值。
    #[test]
    fn gate_roundtrips_through_the_atomic() {
        let s = LinkSignals::new();
        for g in [Gate::Closed, Gate::Throttled, Gate::Open] {
            s.gate.store(g as u8, Ordering::Relaxed);
            assert_eq!(s.gate_state(), g);
            assert_eq!(s.max_extra_copies(), g.max_extra_copies());
        }
    }

    /// 新建的信号必须允许补包：不预设链路有问题。
    ///
    /// 反过来（默认 Closed）会让"采样任务因为任何原因没起来"变成静默的功能失效，
    /// 而且没人会发现。
    #[test]
    fn starts_open_so_a_missing_sampler_does_not_silently_disable_repair() {
        let s = LinkSignals::new();
        assert_eq!(s.gate_state(), Gate::Open);
    }
}
