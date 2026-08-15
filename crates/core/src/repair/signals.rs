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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};
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

/// 发送速率低于 `cwnd/rtt` 的这个比例时，认为是**业务没数据可发**
/// （app-limited），这个样本不能拿来估计链路容量。
///
/// 判据必须是"我们有没有在尽力发"，而不是"队列里有没有东西"——健康链路的
/// 队列在采样时刻永远是空的，用队列做判据等于永远不采样，见采样循环里的说明。
const APP_LIMITED_RATIO: f64 = 0.25;

/// 容量估计每次采样的衰减系数（50ms 一次）。
///
/// 0.999 每秒约衰减到 98%，十秒约 82%——足够慢，不会凭空制造"没余量"，
/// 又足以让链路真的变差之后估计值跟着下来。上一版是 0.995，一秒就掉到 90%，
/// 是闸门被错误关死的直接原因之一。
const BTLBW_DECAY_PER_SAMPLE: f64 = 0.999;

/// QUIC 的初始拥塞窗口（字节）。
///
/// quinn 用的是 RFC 9002 建议的 10 个包，实测读到的就是 12000。
/// 拥塞窗口还等于这个值，说明连接从没把链路压到需要扩窗——
/// 此时任何延迟尖峰都不该被当成排队，见 [`Observation::cwnd_grown`]。
/// 留一点余量用 `>` 比较，避免不同版本的初始值算法差几个字节就失效。
const QUIC_INITIAL_WINDOW_BYTES: u64 = 12_000;

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

    /// 本连接是否真的补过包。风控自校准只在这之后才需要查库，见
    /// [`Self::calibrated_pps_cap`]。
    ever_repaired: AtomicBool,
    /// 风控自校准库 + 本环境指纹 + 已读到的缓存。
    ///
    /// 缓存是为了避免 20Hz 的采样循环每次都去碰数据库；`None` 表示没绑定
    /// （不影响正常工作，只是退化成纯按比例算的预算）。
    #[allow(clippy::type_complexity)]
    calibration: SyncMutex<
        Option<(
            Arc<super::CalibrationStore>,
            String,
            Option<super::Calibration>,
        )>,
    >,

    /// 补发预算，见 [`RepairBudget`]。
    ///
    /// 写入方是采样器（每 50ms 更新速率），读取方是发送路径（每份补发申请一次）。
    /// 用同步锁而不是原子量，是因为令牌桶是有状态的多字段结构，没法拆成独立原子量。
    /// 只在**要发补发包时**才会取这把锁，干净链路上根本不会走到。
    budget: SyncMutex<RepairBudget>,

    // ── 以下仅供日志与诊断，不参与决策 ────────────────────────────
    occupancy_pct: AtomicU8,
    /// 排队延迟梯度 ×100。
    ///
    /// 用 `u16` 不是 `u8`：`u8` 会在 2.55 处饱和，而实测真实梯度轻松超过它——
    /// 一整批 `reason=grad` 的日志全都显示 `grad=2.55`，等于把"到底多严重"
    /// 这个关键信息抹平成一个常量，排障时完全看不出区别。
    gradient_pct: AtomicU16,
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
            ever_repaired: AtomicBool::new(false),
            calibration: SyncMutex::new(None),
            budget: SyncMutex::new(RepairBudget::new(Instant::now())),
            occupancy_pct: AtomicU8::new(0),
            gradient_pct: AtomicU16::new(0),
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
        // 记一笔"这条连接确实补过包"。校准库只在这之后才需要被查——
        // 干净会话根本不用碰数据库。
        self.ever_repaired.store(true, Ordering::Relaxed);
        match self.budget.lock() {
            Ok(mut b) => b.try_admit(len, Instant::now()),
            Err(_) => true,
        }
    }

    /// 绑定风控自校准库。由客户端在启动时调用一次。
    ///
    /// 不绑定也能正常工作，只是拿不到"这个用户环境的历史安全线"，
    /// 退化成纯按比例算的预算。
    pub fn attach_calibration(&self, store: Arc<super::CalibrationStore>, fingerprint: String) {
        if let Ok(mut g) = self.calibration.lock() {
            *g = Some((store, fingerprint, None));
        }
    }

    /// 这个网络环境学到的安全补发包速率上限。
    ///
    /// **只有在本连接真的补过包之后才会去读数据库**，并且读到之后缓存起来，
    /// 不会每 50ms 查一次。链路干净的会话全程返回 `None`，一次 I/O 都不做。
    fn calibrated_pps_cap(&self) -> Option<u32> {
        if !self.ever_repaired.load(Ordering::Relaxed) {
            return None;
        }
        let mut g = self.calibration.lock().ok()?;
        let (store, fp, cached) = g.as_mut()?;
        if let Some(c) = cached {
            return Some(c.max_safe_pps);
        }
        let loaded = store.load(fp);
        let pps = loaded.max_safe_pps;
        *cached = Some(loaded);
        Some(pps)
    }

    /// 会话结束时结算：把这次是"干净"还是"疑似被风控"记进校准库。
    ///
    /// 用户永远不会主动报告"我好像被限速了"，所以只能靠这里自动积累。
    pub fn finish_session(&self, suspected_throttle: bool) {
        let Ok(mut g) = self.calibration.lock() else {
            return;
        };
        let Some((store, fp, cached)) = g.as_mut() else {
            return;
        };
        // 干净且从没补过包的会话没有信息量——它既没验证过上限安全，
        // 也没触发过风控，不该拿去当"又一个干净会话"去推高上限。
        if !suspected_throttle && !self.ever_repaired.load(Ordering::Relaxed) {
            return;
        }
        let mut c = cached.unwrap_or_else(|| store.load(fp));
        if suspected_throttle {
            c.on_suspected_throttle();
        } else {
            c.on_clean_session();
        }
        store.save(fp, &c);
        *cached = Some(c);
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
        let cwnd = self.cwnd_bytes.load(Ordering::Relaxed);
        format!(
            "gate={} reason={} occ={:.2} grad={:.2} srtt={}ms rttmin={}ms cwnd={}B{} headroom={}B/s",
            self.gate_state().as_str(),
            self.reason_str(),
            self.occupancy_pct.load(Ordering::Relaxed) as f32 / 100.0,
            self.gradient_pct.load(Ordering::Relaxed) as f32 / 100.0,
            self.srtt_ms.load(Ordering::Relaxed),
            self.min_rtt_ms.load(Ordering::Relaxed),
            cwnd,
            // 标出"窗口还没长起来"——这种情况下延迟尖峰不代表排队，
            // 排障时看到 `cwnd=12000B(iw)` 就知道该往对端 CPU / 调度那边找，
            // 而不是往网络拥塞上找。
            if cwnd <= QUIC_INITIAL_WINDOW_BYTES {
                "(iw)"
            } else {
                ""
            },
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

            // 出方向实际投递速率。
            let tx_bytes = stats.udp_tx.bytes;
            let delta_bytes = tx_bytes.saturating_sub(prev_tx_bytes);
            prev_tx_bytes = tx_bytes;
            let rate = delta_bytes as f64 / elapsed;

            // 容量估计取窗口内最大投递速率（BBR 的思路）。
            //
            // **上一版这里的采样条件是错的，而且后果严重。** 它写的是
            // "只在 `occupancy > 0` 时才接受采样"，本意是排除 app-limited 的样本
            // （链路空闲时的速率反映的是业务发了多少，不是链路能承载多少）。
            // 但实测证明：健康链路在采样时刻队列**永远是空的**——一整个会话里
            // 每一条日志的 `occ` 都是 0.00。于是 btlbw 从不刷新，只剩下衰减，
            // 几秒内就跌到当前速率以下，`headroom` 归零，闸门被错误地关死。
            // 实测闸门有 75% 的时间是关着的，补包机制等于全程停摆，
            // 而同期 `cwnd` 高达 327KB、链路丢包为 0——那是一条非常健康的链路。
            //
            // 正确的判据不是"队列非空"，而是"**这一刻我们是不是真的在尽力发**"。
            // 用拥塞窗口做参照：发送速率已经接近 `cwnd/rtt` 允许的上限时，
            // 说明是链路在限制我们而不是业务没数据可发，这个样本才反映真实容量。
            let cwnd = stats.path.cwnd as f64;
            let rtt_secs = srtt.as_secs_f64().max(0.001);
            let cwnd_limited_rate = cwnd / rtt_secs;
            let app_limited = rate < cwnd_limited_rate * APP_LIMITED_RATIO;
            if !app_limited && rate > btlbw_bps {
                btlbw_bps = rate;
            } else {
                // 衰减要比上一版慢得多。上一版每 50ms 乘 0.995，一秒就掉到 90%，
                // 十秒只剩 1/3——真正的链路容量不会这样变化，那个速度的衰减
                // 本身就是在制造假的"没余量"。
                btlbw_bps *= BTLBW_DECAY_PER_SAMPLE;
            }

            // 余量 = 估计容量 × 安全边际 − 当前业务速率。
            // 注意这里用的是**当前实际发送速率**，因为源速率对我们是外生的：
            // 没法让游戏少发包，只能决定自己额外加多少。
            //
            // 再用 `cwnd/rtt` 兜一个底：拥塞控制器自己算出来的可发送速率是
            // 第一手信息，比我们观测到的历史最大投递速率更能反映"现在还能发多少"。
            // 两者取大，避免估计器一时没跟上就把闸门误关。
            let capacity = btlbw_bps.max(cwnd_limited_rate);
            let headroom = (capacity * HEADROOM_SAFETY - rate).max(0.0);

            let congestion_events = stats.path.congestion_events;
            let delta_congestion = congestion_events.saturating_sub(prev_congestion_events);
            prev_congestion_events = congestion_events;

            let now_ms = signals.origin.elapsed().as_millis() as u64;
            let obs = Observation {
                self_evicted: signals.recent_self_evict(now_ms),
                occupancy,
                delay_gradient: gradient,
                queueing_delay: srtt.saturating_sub(min_rtt.get().unwrap_or(srtt)),
                // 拥塞窗口长过初始值才算"压过链路"，见 `Observation::cwnd_grown`。
                cwnd_grown: stats.path.cwnd > QUIC_INITIAL_WINDOW_BYTES,
                // 还没有任何容量依据时（连接刚起、cwnd 也还没长起来）不要因为
                // "算出来余量是 0"就误判成拥塞——那时根本谈不上容量估计。
                headroom_bps: if capacity <= 0.0 {
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
            // 风控自校准：把这个用户环境里学到的安全包速率作为补发包速率的上限。
            //
            // **只在真的补过包之后才去查库**，链路干净的会话完全不碰数据库——
            // 绝大多数会话都是干净的，不该为极少数出问题的场景付出每次都查库的
            // 代价。见 `crate::repair::calibration` 的"零开销路径"。
            let learned_cap = signals.calibrated_pps_cap();
            if let Ok(mut b) = signals.budget.lock() {
                b.update(headroom as f32, source_bps, source_pps, now);
                if let Some(cap) = learned_cap {
                    b.clamp_packet_rate(cap as f32);
                }
            }

            // 诊断量
            signals.occupancy_pct.store(
                (occupancy * 100.0).clamp(0.0, 255.0) as u8,
                Ordering::Relaxed,
            );
            signals.gradient_pct.store(
                (gradient * 100.0).clamp(0.0, u16::MAX as f32) as u16,
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
