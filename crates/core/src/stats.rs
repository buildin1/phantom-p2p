//! 隧道统计模块 — 延迟、丢包、流量监控
//!
//! 职责:
//! 1. 记录每个连接的字节数、包数
//! 2. 通过心跳包测量 RTT
//! 3. 计算丢包率
//! 4. 采样带宽(每秒)
//! 5. 提供统计数据查询接口

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

const STALE_STATS_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================
// 统计数据结构
// ============================================================

/// 单个连接的统计信息
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// 用户 ID (session_id 前8位)
    pub user_id: String,
    /// 最近10次 RTT 样本 (毫秒)
    pub latency_samples: VecDeque<u64>,
    /// 发送的包数
    pub packets_sent: u64,
    /// 接收的包数
    pub packets_received: u64,
    /// 丢失的包数
    pub packets_lost: u64,
    /// QUIC 路径层发送包计数（来自 quinn::Connection::stats，连接建立以来的累计值）
    pub quic_sent_packets: u64,
    /// QUIC 路径层丢包计数（来自 quinn::Connection::stats，连接建立以来的累计值）
    pub quic_lost_packets: u64,
    /// 上一次 `update_quic_path_stats` 时的累计值，用于算增量。
    ///
    /// 光有累计值算不出"最近怎么样"：连接开了几十分钟、早期一次性丢了
    /// 500 个包之后一直很干净，累计丢包率会一直卡在一个吓人的历史值上
    /// 不再下降；反过来，游戏中途刚出现的剧烈丢包也会被几十分钟的干净
    /// 历史稀释成看不出来的小数点。前端要展示的是"现在怎么样"，
    /// 必须用两次采样之间的增量算，不能直接拿累计值除累计值。
    prev_quic_sent: u64,
    prev_quic_lost: u64,
    /// 按上面的增量算出的、最近一个采样区间的 QUIC 丢包率（万分之一）。
    pub recent_quic_loss_bp: u16,
    /// 实测**入方向**丢包率（万分之一）。由 overlay 计数器空洞算得，
    /// 本身已经是窗口化的"最近"值，尚无观测时为 None。
    pub inbound_loss_bp: Option<u16>,
    /// 发送的字节数
    pub bytes_sent: u64,
    /// 接收的字节数
    pub bytes_received: u64,
    /// 连接方式 ("p2p" 或 "relay")
    pub connection_mode: String,
    /// 最后一次心跳时间
    pub last_heartbeat: Instant,
}

impl ConnectionStats {
    pub fn new(user_id: String, connection_mode: String) -> Self {
        Self {
            user_id,
            latency_samples: VecDeque::with_capacity(10),
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            quic_sent_packets: 0,
            quic_lost_packets: 0,
            prev_quic_sent: 0,
            prev_quic_lost: 0,
            recent_quic_loss_bp: 0,
            inbound_loss_bp: None,
            bytes_sent: 0,
            bytes_received: 0,
            connection_mode,
            last_heartbeat: Instant::now(),
        }
    }

    /// 获取平均延迟 (毫秒)
    pub fn get_average_latency(&self) -> u64 {
        if self.latency_samples.is_empty() {
            return 0;
        }
        self.latency_samples.iter().sum::<u64>() / self.latency_samples.len() as u64
    }

    /// 获取丢包率 (百分比)——取"**入方向**实测值"和"最近一段 QUIC 出方向丢包率"
    /// 两者较大值。
    ///
    /// 之前这里是 `inbound_loss_bp` 一旦有过任何观测（哪怕是 0）就直接 `return`，
    /// 完全不看 QUIC 那边——而 `inbound_loss_bp` 本身是个短窗口（几秒）实时值，
    /// 干净的那几秒一到就把上一次真实丢包的痕迹冲掉，前端 1 秒轮询一次，
    /// 大概率轮询到的正是"已经冲干净"的那一刻，于是看起来永远是 0%，
    /// 哪怕连接期间真的丢过包（实测联机时出现过：QUIC 自己测出 0.81% 的
    /// 累计丢包，前端却全程显示 0%）。
    ///
    /// 也不能反过来只信 QUIC：它的 `quic_sent_packets`/`quic_lost_packets`
    /// 是**连接建立以来的全量累计值**，早期一次性丢过一批包之后哪怕后面
    /// 干净几十分钟，累计比例也降不回去，一样不反映"现在怎么样"。
    /// 所以 QUIC 这边也要用增量算最近一段的丢包率（`recent_quic_loss_bp`，
    /// 见 `update_quic_path_stats`），不能直接拿累计值除累计值。
    ///
    /// 两个都是"最近"口径，取较大值：`inbound_loss_bp` 测的是对端发给我、
    /// 我没收到的包（真正影响体验的方向），`recent_quic_loss_bp` 测的是我
    /// 发出去的包在传输层的丢包——只要任一方向最近在丢包，都该让用户看见，
    /// 而不是谁把谁盖掉。
    pub fn get_packet_loss_rate(&self) -> f64 {
        let inbound = self.inbound_loss_bp.unwrap_or(0);
        let recent_quic = self.recent_quic_loss_bp;
        if self.inbound_loss_bp.is_some() || self.quic_sent_packets > 0 {
            return inbound.max(recent_quic) as f64 / 100.0;
        }
        if self.packets_sent == 0 {
            return 0.0;
        }
        (self.packets_lost as f64 / self.packets_sent as f64) * 100.0
    }

    /// 添加 RTT 样本
    pub fn add_latency_sample(&mut self, rtt_ms: u64) {
        self.latency_samples.push_back(rtt_ms);
        if self.latency_samples.len() > 10 {
            self.latency_samples.pop_front();
        }
    }

    /// 记录发送数据
    pub fn record_send(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
    }

    /// 记录接收数据
    pub fn record_receive(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
    }
}

/// 带宽采样点 (上行 Mbps, 下行 Mbps)
#[derive(Debug, Clone, serde::Serialize)]
pub struct BandwidthSample {
    pub upload_mbps: f64,
    pub download_mbps: f64,
}

/// 全局统计管理器
pub struct StatsManager {
    /// 是否为 Host
    is_host: Arc<AtomicBool>,
    /// 所有连接的统计信息 (key: user_id)
    connections: Arc<RwLock<HashMap<String, ConnectionStats>>>,
    /// 带宽采样历史 (最近60秒)
    bandwidth_history: Arc<RwLock<VecDeque<BandwidthSample>>>,
    /// 上一次采样时间
    last_sample_time: Arc<RwLock<Instant>>,
    /// 上一次采样时的总发送字节数
    last_bytes_sent: Arc<AtomicU64>,
    /// 上一次采样时的总接收字节数
    last_bytes_received: Arc<AtomicU64>,
}

impl StatsManager {
    pub fn new(is_host: bool) -> Self {
        Self {
            is_host: Arc::new(AtomicBool::new(is_host)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            bandwidth_history: Arc::new(RwLock::new(VecDeque::with_capacity(60))),
            last_sample_time: Arc::new(RwLock::new(Instant::now())),
            last_bytes_sent: Arc::new(AtomicU64::new(0)),
            last_bytes_received: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 设置为 Host 模式
    pub fn set_host_mode(&self, is_host: bool) {
        self.is_host.store(is_host, Ordering::Relaxed);
        debug!("[统计] 模式已切换: is_host={}", is_host);
    }

    /// 添加新连接
    pub async fn add_connection(&self, user_id: String, connection_mode: String) {
        let mut conns = self.connections.write().await;
        debug!(
            "[统计] 添加/更新连接: user_id={}, mode={}",
            user_id, connection_mode
        );
        if let Some(existing) = conns.get_mut(&user_id) {
            existing.connection_mode = connection_mode;
            existing.last_heartbeat = Instant::now();
        } else {
            conns.insert(
                user_id.clone(),
                ConnectionStats::new(user_id, connection_mode),
            );
        }
        debug!("[统计] 当前连接数: {}", conns.len());
    }

    /// 清空所有统计数据（切换会话时调用）
    pub async fn clear(&self) {
        self.connections.write().await.clear();
        self.bandwidth_history.write().await.clear();
        self.last_bytes_sent.store(0, Ordering::Relaxed);
        self.last_bytes_received.store(0, Ordering::Relaxed);
        *self.last_sample_time.write().await = Instant::now();
        debug!("[统计] 已清空所有会话统计");
    }

    /// 移除连接
    pub async fn remove_connection(&self, user_id: &str) {
        let mut conns = self.connections.write().await;
        conns.remove(user_id);
    }

    /// 获取第一个连接 ID（用于尚未显式传入 user_id 的场景）
    pub async fn first_connection_id(&self) -> Option<String> {
        let conns = self.connections.read().await;
        conns.keys().next().cloned()
    }

    /// 记录发送数据
    pub async fn record_send(&self, user_id: &str, bytes: usize) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.record_send(bytes);
        }
    }

    /// 记录接收数据
    pub async fn record_receive(&self, user_id: &str, bytes: usize) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.record_receive(bytes);
        }
    }

    /// 添加延迟样本
    pub async fn add_latency_sample(&self, user_id: &str, rtt_ms: u64) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.add_latency_sample(rtt_ms);
            stats.last_heartbeat = Instant::now();
        }
    }

    /// 更新 QUIC 路径层统计（用于实时丢包率）。
    ///
    /// 调用方（`spawn_quic_monitor`）每秒传入的是**连接建立以来的累计值**，
    /// 这里顺手用跟上一次的差值算一段"最近"的丢包率存进
    /// `recent_quic_loss_bp`，原因见 `get_packet_loss_rate` 的说明。
    pub async fn update_quic_path_stats(
        &self,
        user_id: &str,
        sent_packets: u64,
        lost_packets: u64,
    ) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            // 用 saturating_sub：quinn 的累计计数器只增不减，正常不会倒退，
            // 但连接迁移/重建等边缘情况万一真的倒退了，宁可把这次增量当 0，
            // 也不要下溢算出一个荒谬的丢包率。
            let delta_sent = sent_packets.saturating_sub(stats.prev_quic_sent);
            let delta_lost = lost_packets.saturating_sub(stats.prev_quic_lost);
            if delta_sent > 0 {
                stats.recent_quic_loss_bp = ((delta_lost * 10_000) / delta_sent).min(10_000) as u16;
            }
            stats.prev_quic_sent = sent_packets;
            stats.prev_quic_lost = lost_packets;
            stats.quic_sent_packets = sent_packets;
            stats.quic_lost_packets = lost_packets;
        }
    }

    /// 更新实测的**入方向**丢包率（万分之一）。
    ///
    /// 由 `tun_bridge` 按 overlay 计数器空洞算出。这是唯一能反映
    /// "对端发给我、我没收到"的口径，也是唯一与体验相关的那个方向。
    pub async fn update_inbound_loss(&self, user_id: &str, loss_bp: u16) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.inbound_loss_bp = Some(loss_bp);
        }
    }

    /// 更新连接模式（p2p/relay）
    pub async fn set_connection_mode(&self, user_id: &str, connection_mode: &str) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.connection_mode = connection_mode.to_string();
        }
    }

    /// 采样带宽 (每秒调用一次)
    pub async fn sample_bandwidth(&self) {
        let mut last_time = self.last_sample_time.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_time).as_secs_f64();

        if elapsed >= 1.0 {
            // 清理长时间无心跳的残留连接，防止 UI 永久显示僵尸 ID
            {
                let mut conns = self.connections.write().await;
                conns.retain(|_, s| now.duration_since(s.last_heartbeat) <= STALE_STATS_TIMEOUT);
            }

            // 计算总字节数
            let conns = self.connections.read().await;
            let total_sent: u64 = conns.values().map(|s| s.bytes_sent).sum();
            let total_recv: u64 = conns.values().map(|s| s.bytes_received).sum();
            drop(conns);

            // 计算增量
            let last_sent = self.last_bytes_sent.load(Ordering::Relaxed);
            let last_recv = self.last_bytes_received.load(Ordering::Relaxed);

            let sent_delta = total_sent.saturating_sub(last_sent);
            let recv_delta = total_recv.saturating_sub(last_recv);

            // 计算 Mbps
            let upload_mbps = (sent_delta as f64 * 8.0) / elapsed / 1_000_000.0;
            let download_mbps = (recv_delta as f64 * 8.0) / elapsed / 1_000_000.0;

            // 保存样本
            let mut history = self.bandwidth_history.write().await;
            history.push_back(BandwidthSample {
                upload_mbps,
                download_mbps,
            });
            if history.len() > 60 {
                history.pop_front();
            }

            // 更新状态
            self.last_bytes_sent.store(total_sent, Ordering::Relaxed);
            self.last_bytes_received
                .store(total_recv, Ordering::Relaxed);
            *last_time = now;

            debug!(
                "[统计] 带宽采样: 上行 {:.2} Mbps, 下行 {:.2} Mbps",
                upload_mbps, download_mbps
            );
        }
    }

    /// 获取当前统计数据 (供 Tauri 命令使用)
    pub async fn get_stats(&self) -> StatsResponse {
        let conns = self.connections.read().await;
        let history = self.bandwidth_history.read().await;
        let is_host = self.is_host.load(Ordering::Relaxed);

        debug!(
            "[统计] get_stats 被调用, is_host={}, 连接数={}",
            is_host,
            conns.len()
        );

        // 计算总流量
        let total_sent: u64 = conns.values().map(|s| s.bytes_sent).sum();
        let total_recv: u64 = conns.values().map(|s| s.bytes_received).sum();
        let total_traffic = total_sent + total_recv;

        // 当前带宽
        let current_bandwidth = history.back().cloned().unwrap_or(BandwidthSample {
            upload_mbps: 0.0,
            download_mbps: 0.0,
        });

        if is_host {
            // Host 端: 返回所有玩家信息
            let players: Vec<PlayerInfo> = conns
                .values()
                .map(|stats| PlayerInfo {
                    user_id: stats.user_id.clone(),
                    latency: stats.get_average_latency(),
                    packet_loss: stats.get_packet_loss_rate(),
                    connection_mode: stats.connection_mode.clone(),
                })
                .collect();

            // 计算平均延迟和丢包率
            let avg_latency = if players.is_empty() {
                0
            } else {
                players.iter().map(|p| p.latency).sum::<u64>() / players.len() as u64
            };

            let avg_packet_loss = if players.is_empty() {
                0.0
            } else {
                players.iter().map(|p| p.packet_loss).sum::<f64>() / players.len() as f64
            };

            StatsResponse {
                is_host: true,
                latency: avg_latency,
                packet_loss: avg_packet_loss,
                connection_mode: "p2p".to_string(),
                total_traffic,
                total_upload_bytes: total_sent,
                total_download_bytes: total_recv,
                upload_mbps: current_bandwidth.upload_mbps,
                download_mbps: current_bandwidth.download_mbps,
                upload_history: history.iter().map(|s| s.upload_mbps).collect(),
                download_history: history.iter().map(|s| s.download_mbps).collect(),
                online_count: players.len(),
                players: Some(players),
            }
        } else {
            // Guest 端: 只返回自己的信息
            let (latency, packet_loss, connection_mode) = if let Some(stats) = conns.values().next()
            {
                (
                    stats.get_average_latency(),
                    stats.get_packet_loss_rate(),
                    stats.connection_mode.clone(),
                )
            } else {
                (0, 0.0, "p2p".to_string())
            };

            StatsResponse {
                is_host: false,
                latency,
                packet_loss,
                connection_mode,
                total_traffic,
                total_upload_bytes: total_sent,
                total_download_bytes: total_recv,
                upload_mbps: current_bandwidth.upload_mbps,
                download_mbps: current_bandwidth.download_mbps,
                upload_history: history.iter().map(|s| s.upload_mbps).collect(),
                download_history: history.iter().map(|s| s.download_mbps).collect(),
                online_count: 0,
                players: None,
            }
        }
    }

    /// 启动后台采样任务
    pub fn start_sampling_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                self.sample_bandwidth().await;
            }
        });
    }
}

// ============================================================
// 响应数据结构
// ============================================================

/// 玩家信息 (Host 端使用)
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlayerInfo {
    pub user_id: String,
    pub latency: u64,
    pub packet_loss: f64,
    pub connection_mode: String,
}

/// 统计数据响应
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsResponse {
    pub is_host: bool,
    pub latency: u64,
    pub packet_loss: f64,
    pub connection_mode: String,
    pub total_traffic: u64,
    pub total_upload_bytes: u64,
    pub total_download_bytes: u64,
    pub upload_mbps: f64,
    pub download_mbps: f64,
    pub upload_history: Vec<f64>,
    pub download_history: Vec<f64>,
    pub online_count: usize,
    pub players: Option<Vec<PlayerInfo>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归测试：这就是实机联机测出来的那个 bug——`inbound_loss_bp` 只要被
    /// 观测过一次（哪怕是 0），旧代码会直接 `return`，QUIC 自己测到的
    /// 累计丢包就永远显示不出来。
    #[test]
    fn quic_loss_is_not_masked_by_a_clean_inbound_reading() {
        let mut stats = ConnectionStats::new("u1".into(), "p2p".into());
        stats.inbound_loss_bp = Some(0); // 最近这一刻入方向是干净的
        stats.quic_sent_packets = 1000;
        stats.recent_quic_loss_bp = 200; // 但 QUIC 那边最近测到 2% 丢包
        assert_eq!(stats.get_packet_loss_rate(), 2.0);
    }

    /// 入方向如果比 QUIC 那边更高，也不能被 QUIC 的低值压下去——
    /// 两个方向哪个在丢包都要能看见。
    #[test]
    fn inbound_loss_wins_when_higher_than_quic() {
        let mut stats = ConnectionStats::new("u1".into(), "p2p".into());
        stats.inbound_loss_bp = Some(3000); // 30%
        stats.quic_sent_packets = 1000;
        stats.recent_quic_loss_bp = 50;
        assert_eq!(stats.get_packet_loss_rate(), 30.0);
    }

    /// 没有任何观测时不能报丢包。
    #[test]
    fn reports_zero_before_any_observation() {
        let stats = ConnectionStats::new("u1".into(), "p2p".into());
        assert_eq!(stats.get_packet_loss_rate(), 0.0);
    }

    /// `update_quic_path_stats` 存的是**增量**丢包率，不是累计值直接相除——
    /// 早期一次性丢了一批包之后，只要后面这次增量是干净的，`recent_quic_loss_bp`
    /// 就该回落，不能被历史累计值锁死在高位。
    #[tokio::test]
    async fn quic_loss_rate_reflects_the_recent_window_not_lifetime_cumulative() {
        let manager = StatsManager::new(true);
        manager.add_connection("u1".into(), "p2p".into()).await;

        // 第一次采样：早期一次性丢了 100/1000，累计丢包率 10%。
        manager.update_quic_path_stats("u1", 1000, 100).await;
        {
            let conns = manager.connections.read().await;
            let s = conns.get("u1").unwrap();
            assert_eq!(s.recent_quic_loss_bp, 1000); // 10.00%
        }

        // 第二次采样：这段区间新发了 1000 个、一个没丢——
        // 最近一段应该是 0%，不能还停在 10%。
        manager.update_quic_path_stats("u1", 2000, 100).await;
        {
            let conns = manager.connections.read().await;
            let s = conns.get("u1").unwrap();
            assert_eq!(s.recent_quic_loss_bp, 0);
            // 但累计丢包率字段本身还是要如实反映 QUIC 报告的全量累计值，
            // 不能因为要算增量就把原始数据弄丢。
            assert_eq!(s.quic_sent_packets, 2000);
            assert_eq!(s.quic_lost_packets, 100);
        }
    }
}
