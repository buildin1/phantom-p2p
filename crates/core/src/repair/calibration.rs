//! 运营商风控的按环境自校准。
//!
//! # 为什么必须自校准，而不是写死一个上限
//!
//! 《踩坑记录》第十一条记的是实测：有用户用高包速率的代理约 **2 分钟就被运营商
//! 掐断**；早期做多倍发包实验时，TCP 游戏下玩家被**直接踢出**。同时那条也写明
//! 了**阈值各地不同、用户无法预先测**——同一个数字在这个用户家里安全，
//! 在另一个用户家里就触发风控。
//!
//! 所以正确做法只能是：**在每个用户自己的环境里，自己找出那条线**。
//!
//! # 设计原则：把用户当作什么都不会做
//!
//! 用户不会去翻日志，甚至不知道日志在哪，更不会主动报告"我被限速了"。
//! 所以这套东西必须：
//!
//! * **全自动**：启动即加载，出问题即降档，全程无需任何用户操作
//! * **持久化**：这次学到的教训下次开机还在，不能每次重来
//! * **零开销路径**：链路干净时**完全不碰数据库**——绝大多数会话都是干净的，
//!   不该为极少数出问题的场景付出每次启动查库的代价
//!
//! # 保守起步、缓慢上探
//!
//! 降档是立即的（一次疑似风控就降），上探是缓慢的（要连续多个干净会话才敢加一档）。
//! 跟闸门和预算的非对称设计同一个道理：踩坑的代价（用户被掐断、游戏被踢）
//! 远高于保守一点的代价（补包少一点）。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 判定疑似风控之后，把安全上限降到当前值的这个比例。
const THROTTLE_BACKOFF: f32 = 0.7;
/// 连续多少个干净会话之后才允许上探一档。
const CLEAN_SESSIONS_BEFORE_PROBE: u32 = 3;
/// 每次上探把上限抬高的比例。
const PROBE_STEP: f32 = 1.25;
/// 没有任何历史时的保守起点（补发包/秒）。
///
/// 取《踩坑记录》第十一条里"5 人整局双发后约 300 包/秒"那个已知安全的量级，
/// 再打个折——那是整局的总量，我们这里是单条连接的补发量。
const DEFAULT_SAFE_PPS: u32 = 120;
/// 无论学到什么都不允许突破的硬顶。
const ABSOLUTE_MAX_PPS: u32 = 300;

/// 一条链路环境的校准结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibration {
    /// 实测未触发风控的最高补发包速率
    pub max_safe_pps: u32,
    /// 疑似被风控的累计次数
    pub throttle_events: u32,
    /// 连续无风控事件的会话数
    pub clean_sessions: u32,
}

impl Default for Calibration {
    fn default() -> Self {
        Self {
            max_safe_pps: DEFAULT_SAFE_PPS,
            throttle_events: 0,
            clean_sessions: 0,
        }
    }
}

impl Calibration {
    /// 记一次疑似风控：立即降档。
    pub fn on_suspected_throttle(&mut self) {
        self.throttle_events = self.throttle_events.saturating_add(1);
        self.clean_sessions = 0;
        // 降到七成，但不低于一个还能起作用的下限——降到 0 等于永久关掉补包，
        // 那是过度反应。
        self.max_safe_pps = ((self.max_safe_pps as f32 * THROTTLE_BACKOFF) as u32).max(20);
    }

    /// 记一个干净会话：够多之后允许上探一档。
    pub fn on_clean_session(&mut self) {
        self.clean_sessions = self.clean_sessions.saturating_add(1);
        if self.clean_sessions >= CLEAN_SESSIONS_BEFORE_PROBE {
            self.clean_sessions = 0;
            self.max_safe_pps =
                ((self.max_safe_pps as f32 * PROBE_STEP) as u32).min(ABSOLUTE_MAX_PPS);
        }
    }
}

/// 判断这次会话是不是疑似被运营商风控。
///
/// **不能只看"吞吐掉下去了"**——那跟普通拥塞分不开。风控的特征是：
/// 本端没有观察到任何拥塞迹象（队列不满、排队延迟正常），吞吐却断崖式下跌，
/// 或者连接在持续高包速率之后被莫名重置。拥塞会先让延迟涨起来，风控不会。
///
/// 纯逻辑，方便单测。
pub fn looks_like_throttling(
    repair_pps: u32,
    throughput_drop_ratio: f32,
    queueing_delay_ms: u64,
    connection_reset: bool,
) -> bool {
    // 补发速率很低时不该赖到风控头上——那个量级根本不构成风控特征
    if repair_pps < 30 {
        return false;
    }
    // 排队延迟明显上涨说明是拥塞，不是风控
    if queueing_delay_ms > 30 {
        return false;
    }
    connection_reset || throughput_drop_ratio > 0.6
}

/// 按网络环境索引的校准库。
pub struct CalibrationStore {
    path: PathBuf,
}

impl CalibrationStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("calibration.db"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 打开（必要时创建）数据库。
    ///
    /// 失败一律降级为"用默认值"，绝不让校准库的问题影响联机——它是优化手段，
    /// 不是必需品。
    fn open(&self) -> Option<rusqlite::Connection> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = rusqlite::Connection::open(&self.path).ok()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS calibration (
                fingerprint     TEXT PRIMARY KEY,
                max_safe_pps    INTEGER NOT NULL,
                throttle_events INTEGER NOT NULL,
                clean_sessions  INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL
            )",
            [],
        )
        .ok()?;
        Some(conn)
    }

    /// 读取某个网络环境的校准值。没有记录就返回默认值。
    ///
    /// **只在检测到丢包时才该调用**——链路干净的会话不需要查库，
    /// 见模块文档的"零开销路径"。
    pub fn load(&self, fingerprint: &str) -> Calibration {
        let Some(conn) = self.open() else {
            return Calibration::default();
        };
        conn.query_row(
            "SELECT max_safe_pps, throttle_events, clean_sessions
             FROM calibration WHERE fingerprint = ?1",
            [fingerprint],
            |row| {
                Ok(Calibration {
                    max_safe_pps: row.get::<_, i64>(0)? as u32,
                    throttle_events: row.get::<_, i64>(1)? as u32,
                    clean_sessions: row.get::<_, i64>(2)? as u32,
                })
            },
        )
        .unwrap_or_default()
    }

    /// 写回校准值。失败静默——校准是优化，不是必需品。
    pub fn save(&self, fingerprint: &str, c: &Calibration) {
        let Some(conn) = self.open() else { return };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let _ = conn.execute(
            "INSERT INTO calibration
                (fingerprint, max_safe_pps, throttle_events, clean_sessions, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(fingerprint) DO UPDATE SET
                max_safe_pps    = excluded.max_safe_pps,
                throttle_events = excluded.throttle_events,
                clean_sessions  = excluded.clean_sessions,
                updated_at      = excluded.updated_at",
            rusqlite::params![
                fingerprint,
                c.max_safe_pps as i64,
                c.throttle_events as i64,
                c.clean_sessions as i64,
                now
            ],
        );
    }
}

/// 网络环境指纹。
///
/// 用出口公网 IP 的前缀 + NAT 类型，而不是完整 IP：同一个运营商同一个区域的
/// 风控策略是一致的，用完整 IP 会让每次换 IP（拨号、移动网络）都从零开始学。
pub fn fingerprint(public_ip: Option<&str>, nat_class: &str) -> String {
    let prefix = public_ip
        .and_then(|ip| {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                Some(format!("{}.{}", parts[0], parts[1]))
            } else {
                // IPv6 或异常输入：取前两段
                ip.split(':').take(2).collect::<Vec<_>>().join(":").into()
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    format!("{}|{}", prefix, nat_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 疑似风控要立即降档，不能等。
    #[test]
    fn a_suspected_throttle_backs_off_immediately() {
        let mut c = Calibration::default();
        let before = c.max_safe_pps;
        c.on_suspected_throttle();
        assert!(c.max_safe_pps < before, "必须立即降档");
        assert_eq!(c.throttle_events, 1);
        assert_eq!(c.clean_sessions, 0, "干净计数要清零重来");
    }

    /// 降档不能降到 0——那等于永久关掉补包，是过度反应。
    #[test]
    fn backoff_never_reaches_zero() {
        let mut c = Calibration::default();
        for _ in 0..50 {
            c.on_suspected_throttle();
        }
        assert!(c.max_safe_pps >= 20, "实得 {}", c.max_safe_pps);
    }

    /// 上探必须缓慢：单个干净会话不足以加档。
    #[test]
    fn probing_upward_requires_several_clean_sessions() {
        let mut c = Calibration::default();
        let start = c.max_safe_pps;
        c.on_clean_session();
        assert_eq!(c.max_safe_pps, start, "一个干净会话还不够");
        c.on_clean_session();
        assert_eq!(c.max_safe_pps, start, "两个也不够");
        c.on_clean_session();
        assert!(c.max_safe_pps > start, "第三个才允许上探");
    }

    /// 上探有硬顶，学不出一个危险的值。
    #[test]
    fn probing_respects_the_absolute_ceiling() {
        let mut c = Calibration::default();
        for _ in 0..200 {
            c.on_clean_session();
        }
        assert!(
            c.max_safe_pps <= ABSOLUTE_MAX_PPS,
            "实得 {}",
            c.max_safe_pps
        );
    }

    /// **拥塞不能被误判成风控。** 两者的应对完全不同：
    /// 拥塞要降补发量，风控要降包速率并持久化记住。
    #[test]
    fn congestion_is_not_mistaken_for_throttling() {
        // 吞吐掉了很多，但排队延迟同时涨上去了 → 这是拥塞
        assert!(
            !looks_like_throttling(100, 0.8, 80, false),
            "排队延迟涨了就是拥塞，不是风控"
        );
    }

    /// 风控的特征：没有拥塞迹象，吞吐却断崖下跌。
    #[test]
    fn a_throughput_cliff_without_queueing_looks_like_throttling() {
        assert!(looks_like_throttling(100, 0.8, 5, false));
    }

    /// 高包速率下被莫名重置，也算疑似风控。
    #[test]
    fn an_unexplained_reset_at_high_rate_counts() {
        assert!(looks_like_throttling(100, 0.0, 5, true));
    }

    /// 补发量本来就很低时不该赖到风控头上。
    #[test]
    fn low_repair_rates_are_never_blamed_on_throttling() {
        assert!(!looks_like_throttling(5, 0.9, 0, true));
    }

    /// 指纹按网段而不是完整 IP：换 IP 不该让学到的东西全部作废。
    #[test]
    fn fingerprint_groups_by_network_not_exact_ip() {
        let a = fingerprint(Some("27.190.194.94"), "cone");
        let b = fingerprint(Some("27.190.200.1"), "cone");
        assert_eq!(a, b, "同一运营商同一区域应共享校准");

        let c = fingerprint(Some("58.37.2.105"), "cone");
        assert_ne!(a, c, "不同网段要分开");

        let d = fingerprint(Some("27.190.194.94"), "symmetric_random");
        assert_ne!(a, d, "NAT 类型不同要分开");
    }

    /// 存取往返，并且没有记录时给默认值。
    #[test]
    fn store_roundtrips_and_defaults_when_absent() {
        let dir = std::env::temp_dir().join(format!("phantom-cal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = CalibrationStore::new(&dir);

        assert_eq!(
            store.load("nope|cone"),
            Calibration::default(),
            "没有记录时必须给保守默认值"
        );

        let mut c = Calibration::default();
        c.on_suspected_throttle();
        store.save("27.190|cone", &c);
        assert_eq!(store.load("27.190|cone"), c, "这次学到的下次要还在");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
