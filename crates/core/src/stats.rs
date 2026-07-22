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
    /// QUIC 路径层发送包计数（来自 quinn::Connection::stats）
    pub quic_sent_packets: u64,
    /// QUIC 路径层丢包计数（来自 quinn::Connection::stats）
    pub quic_lost_packets: u64,
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

    /// 获取丢包率 (百分比)
    pub fn get_packet_loss_rate(&self) -> f64 {
        // 优先使用 QUIC 路径层统计，反映真实网络丢包
        if self.quic_sent_packets > 0 {
            return (self.quic_lost_packets as f64 / self.quic_sent_packets as f64) * 100.0;
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

    /// 更新 QUIC 路径层统计（用于实时丢包率）
    pub async fn update_quic_path_stats(
        &self,
        user_id: &str,
        sent_packets: u64,
        lost_packets: u64,
    ) {
        let mut conns = self.connections.write().await;
        if let Some(stats) = conns.get_mut(user_id) {
            stats.quic_sent_packets = sent_packets;
            stats.quic_lost_packets = lost_packets;
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
