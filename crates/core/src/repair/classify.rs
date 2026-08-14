//! 按流特征决定"这条流值不值得补包"。
//!
//! # 为什么需要分流，而不是一个连接一个档位
//!
//! 上一版的连接级预测基线是对**每一个包**生效的：对端一报非零丢包率，
//! 连接上所有流的档位一起抬——**包括那条正在把链路占满的批量下载流**。
//! 把一条已经饱和的流三倍，是填满发送队列最快的方式。这是实测崩溃的根因之一。
//!
//! 补包对不同流量的价值差别极大：
//!
//! | 流量类型 | 补包价值 | 原因 |
//! |---|---|---|
//! | 批量传输（HTTP/HTTPS 下载、区块同步） | **接近零** | 吞吐受带宽限制，复制等于自己抢自己的带宽；内层 TCP 本来就会重传 |
//! | 交互式小包（游戏状态、聊天、ACK） | **高** | 丢一个就是一次可感知的卡顿/回弹，而且量小，补起来几乎不花带宽 |
//! | 实时 UDP | **高** | 没有内层重传兜底，丢了就是真丢 |
//! | TCP 握手/挥手 | **最高** | 丢一个 SYN 就是一秒 RTO，是整个会话里最显眼的停顿 |
//!
//! # 主判据是包尺寸，不是流标签
//!
//! Minecraft Java 在**同一条 TCP 连接**上先下区块再进入交互——同一个五元组、
//! 同一个 `FlowKey`。任何粘在流上的标签在构造上就是错的，而实测崩溃恰好就发生在
//! 这个转换点上。
//!
//! 包尺寸没有这个问题：它零状态、零滞后、不可能"粘错"。批量传输几乎全是 MSS 满包
//! （本隧道 `TUN_MTU` 1160 → 内层 MSS 约 1120），而游戏状态、ACK、心跳、ICMP
//! 都远小于此。于是"边下区块边移动"时，同一毫秒内的区块包和移动包会被正确地
//! 区别对待——**这是任何流级分类器都做不到的**。
//!
//! 流状态只作为辅助判据，并且用**非对称迟滞**：进入批量态要连续 1 秒的证据
//! （防止一次突发被误判），退出只要 200ms（区块下完立刻恢复保护）。

use std::time::{Duration, Instant};

/// 超过 `TUN_MTU` 的这个比例就认为是"满包"，即批量传输。
///
/// 不取 1.0 是因为不同实现的 MSS 协商会差几个字节，卡死在等于会漏掉一部分满包。
const BULK_PACKET_RATIO: f32 = 0.9;

/// 进入批量态需要证据持续多久。
const BULK_ENTER_DWELL: Duration = Duration::from_millis(1000);
/// 退出批量态需要证据消失多久。**必须远短于进入**，见模块文档。
const BULK_EXIT_DWELL: Duration = Duration::from_millis(200);

/// 判定为批量流的速率门槛（字节/秒）。
const BULK_RATE_BPS: f32 = 200_000.0;

/// EWMA 时间常数。
const EWMA_TAU: Duration = Duration::from_millis(500);

/// 实时 UDP 的判定：平均包长小于此且频率高于下面那个阈值。
const REALTIME_UDP_MAX_SIZE: f32 = 300.0;
const REALTIME_UDP_MIN_PPS: f32 = 10.0;

/// 流的类别，决定补包上限。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlowClass {
    /// 批量传输：不补。吞吐受带宽限制，复制只会抢自己的带宽。
    Bulk,
    /// 交互式：补包价值最高。
    Interactive,
    /// 实时 UDP：没有内层重传兜底。
    RealtimeUdp,
    /// 低频流（ICMP 等）：值得补，但本来也没多少包。
    Sparse,
    /// 还看不出来：保守对待。
    Unknown,
}

impl FlowClass {
    /// 这一类允许的最大补发份数。
    pub fn max_extra_copies(self) -> u8 {
        match self {
            FlowClass::Bulk => 0,
            FlowClass::Interactive | FlowClass::RealtimeUdp => 2,
            FlowClass::Sparse => 1,
            // 没看清楚之前保守：补 1 份的代价很小，补错了也不至于压垮链路。
            FlowClass::Unknown => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FlowClass::Bulk => "bulk",
            FlowClass::Interactive => "inter",
            FlowClass::RealtimeUdp => "rt",
            FlowClass::Sparse => "sparse",
            FlowClass::Unknown => "unknown",
        }
    }
}

/// **主判据**：这个包本身是不是批量传输的满包。
///
/// 零状态、零滞后。返回 `true` 表示不该给它补包。
///
/// 这条规则独立于流的类别生效，所以即使一条流刚被判成批量态、标签还没来得及
/// 翻转，它上面的**小包**（玩家移动、聊天）依然受保护。
pub fn is_bulk_sized(packet_len: usize, tun_mtu: u16) -> bool {
    packet_len as f32 >= tun_mtu as f32 * BULK_PACKET_RATIO
}

/// TCP 控制包（SYN/FIN/RST）——丢一个的代价远高于多发一个。
///
/// `flags` 是 TCP 首部第 13 字节。SYN=0x02，FIN=0x01，RST=0x04。
pub fn is_tcp_control(flags: u8) -> bool {
    flags & 0b0000_0111 != 0
}

/// 单条流的运行画像。
#[derive(Clone, Debug)]
pub struct FlowProfile {
    bytes_ewma: f32,
    pkts_ewma: f32,
    size_ewma: f32,
    last_update: Instant,
    /// 批量证据**开始**连续出现的时刻
    bulk_evidence_since: Option<Instant>,
    /// 批量证据**消失**的时刻（仅在当前是批量态时有意义）
    bulk_absent_since: Option<Instant>,
    class: FlowClass,
    protocol: u8,
}

impl FlowProfile {
    pub fn new(protocol: u8, now: Instant) -> Self {
        Self {
            bytes_ewma: 0.0,
            pkts_ewma: 0.0,
            size_ewma: 0.0,
            last_update: now,
            bulk_evidence_since: None,
            bulk_absent_since: None,
            class: FlowClass::Unknown,
            protocol,
        }
    }

    pub fn class(&self) -> FlowClass {
        self.class
    }

    pub fn last_update(&self) -> Instant {
        self.last_update
    }

    /// 观测一个包，更新画像并重新分类。
    pub fn observe(&mut self, packet_len: usize, tun_mtu: u16, now: Instant) {
        let dt = now.duration_since(self.last_update).as_secs_f32();
        self.last_update = now;

        // 按时间衰减的 EWMA：包间隔不规则，不能按包数算权重。
        let alpha = if dt <= 0.0 {
            0.0
        } else {
            1.0 - (-dt / EWMA_TAU.as_secs_f32()).exp()
        };
        let inst_rate = if dt > 0.0 {
            packet_len as f32 / dt
        } else {
            self.bytes_ewma
        };
        let inst_pps = if dt > 0.0 { 1.0 / dt } else { self.pkts_ewma };

        self.bytes_ewma += alpha * (inst_rate - self.bytes_ewma);
        self.pkts_ewma += alpha * (inst_pps - self.pkts_ewma);
        self.size_ewma += alpha * (packet_len as f32 - self.size_ewma);

        self.reclassify(tun_mtu, now);
    }

    fn reclassify(&mut self, tun_mtu: u16, now: Instant) {
        let bulk_evidence =
            self.bytes_ewma > BULK_RATE_BPS && self.size_ewma > tun_mtu as f32 * 0.8;

        if bulk_evidence {
            self.bulk_absent_since = None;
            let since = *self.bulk_evidence_since.get_or_insert(now);
            if now.duration_since(since) >= BULK_ENTER_DWELL {
                self.class = FlowClass::Bulk;
                return;
            }
        } else {
            self.bulk_evidence_since = None;
            if self.class == FlowClass::Bulk {
                let absent = *self.bulk_absent_since.get_or_insert(now);
                if now.duration_since(absent) < BULK_EXIT_DWELL {
                    // 还在退出迟滞里，保持批量态
                    return;
                }
                // 迟滞走完，落回下面的常规分类
                self.bulk_absent_since = None;
            }
        }

        if self.class == FlowClass::Bulk && bulk_evidence {
            return;
        }

        self.class = match self.protocol {
            // ICMP：低频，ping 就是用户盯着看的那个数，值得补且几乎不花钱
            1 => FlowClass::Sparse,
            17 if self.size_ewma < REALTIME_UDP_MAX_SIZE
                && self.pkts_ewma > REALTIME_UDP_MIN_PPS =>
            {
                FlowClass::RealtimeUdp
            }
            6 | 17 => FlowClass::Interactive,
            _ => FlowClass::Unknown,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1160;

    /// 满包就是批量，零状态判定。
    #[test]
    fn full_sized_packets_are_bulk() {
        assert!(is_bulk_sized(1160, MTU));
        assert!(is_bulk_sized(1100, MTU), "略小于 MTU 的满包也要算");
        assert!(!is_bulk_sized(145, MTU), "典型游戏包不是批量");
        assert!(!is_bulk_sized(52, MTU), "纯 ACK 不是批量");
    }

    /// **生产故障的那个转换点。**
    ///
    /// MC 在同一条 TCP 连接上先下区块再交互。区块下完之后，保护必须很快恢复，
    /// 否则交互阶段就是裸奔——实测崩溃正是发生在这里。
    #[test]
    fn bulk_to_interactive_transition_restores_protection_quickly() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut p = FlowProfile::new(6, t);

        // 阶段一：狂下区块，满包高速率，持续 2 秒
        let mut now = t;
        for _ in 0..400 {
            now += ms(5);
            p.observe(1160, MTU, now);
        }
        assert_eq!(p.class(), FlowClass::Bulk, "持续满包高速率应判为批量");
        assert_eq!(p.class().max_extra_copies(), 0, "批量流不补包");

        // 阶段二：区块下完，转入交互（小包、低速率）
        for _ in 0..10 {
            now += ms(50);
            p.observe(145, MTU, now);
        }
        assert_eq!(
            p.class(),
            FlowClass::Interactive,
            "转入交互 500ms 内必须恢复保护，否则交互阶段裸奔"
        );
        assert!(p.class().max_extra_copies() > 0);
    }

    /// 进入批量态要慢：一次短暂突发不该让整条流失去保护。
    #[test]
    fn a_short_burst_does_not_get_classified_as_bulk() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut p = FlowProfile::new(6, t);
        let mut now = t;
        // 只突发 300ms，不到 1 秒的进入迟滞
        for _ in 0..60 {
            now += ms(5);
            p.observe(1160, MTU, now);
        }
        assert_ne!(p.class(), FlowClass::Bulk, "短突发不该被判成批量");
    }

    /// 即使流被判成批量，它上面的小包依然受尺寸规则保护。
    ///
    /// 这是尺寸规则相对流级分类器的核心优势：同一毫秒里的区块包和移动包
    /// 会被区别对待。
    #[test]
    fn interactive_packets_on_a_bulk_flow_are_still_protected() {
        // 流是批量态
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut p = FlowProfile::new(6, t);
        let mut now = t;
        for _ in 0..400 {
            now += ms(5);
            p.observe(1160, MTU, now);
        }
        assert_eq!(p.class(), FlowClass::Bulk);

        // 但一个小包不该被尺寸规则拦下
        assert!(!is_bulk_sized(145, MTU), "批量流上的小包必须仍然能拿到保护");
    }

    /// TCP 握手包永远值得补：丢一个 SYN 是一秒 RTO。
    #[test]
    fn tcp_handshake_packets_are_recognised() {
        assert!(is_tcp_control(0x02), "SYN");
        assert!(is_tcp_control(0x12), "SYN-ACK");
        assert!(is_tcp_control(0x01), "FIN");
        assert!(is_tcp_control(0x04), "RST");
        assert!(!is_tcp_control(0x10), "纯 ACK 不是控制包");
        assert!(!is_tcp_control(0x18), "PSH-ACK 是数据包");
    }

    /// 高频小包 UDP = 实时流量，没有内层重传兜底，补包价值高。
    #[test]
    fn frequent_small_udp_is_realtime() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut p = FlowProfile::new(17, t);
        let mut now = t;
        for _ in 0..100 {
            now += ms(20); // 50pps
            p.observe(120, MTU, now);
        }
        assert_eq!(p.class(), FlowClass::RealtimeUdp);
        assert!(p.class().max_extra_copies() > 0);
    }

    /// ICMP 归为低频流：ping 是用户直接盯着的指标。
    #[test]
    fn icmp_is_sparse_and_still_protected() {
        let t = Instant::now();
        let mut p = FlowProfile::new(1, t);
        p.observe(84, MTU, t + Duration::from_secs(1));
        assert_eq!(p.class(), FlowClass::Sparse);
        assert!(p.class().max_extra_copies() > 0, "ping 值得补");
    }

    /// 没见过的协议保守对待，但不能是 0——否则一个没覆盖到的协议就静默失去保护。
    #[test]
    fn unknown_protocol_is_conservative_but_not_unprotected() {
        assert_eq!(FlowClass::Unknown.max_extra_copies(), 1);
    }
}
