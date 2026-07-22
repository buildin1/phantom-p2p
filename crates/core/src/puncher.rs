//! UDP 打洞引擎（ICE 增强版）
//!
//! 新版流程：
//! 1. 绑定 UDP socket
//! 2. STUN 探测 + ICE 候选收集（多服务器 + 端口预测）
//! 3. 通过信令上报 IceCandidates
//! 4. 等待信令转发对端 PeerCandidates
//! 5. ICE 连通性检测：同时向对端所有候选发 PUNCH_MAGIC
//! 6. 最先响应的候选胜出 → 成功
//! 7. 超时 → 失败，使用预分配中继

use crate::ice;
use phantom_protocol::IceCandidate;
use std::net::UdpSocket;
use std::sync::Arc;
use tracing::{info, warn};

/// 打洞结果
#[derive(Debug, Clone)]
pub struct PunchResult {
    /// 是否成功
    pub success: bool,
    /// 成功时对方地址
    pub peer_addr: String,
    /// RTT 毫秒
    pub latency_ms: u32,
    /// 失败原因
    pub reason: String,
}

/// 打洞阶段状态（用于前端展示）
#[derive(Debug, Clone, serde::Serialize)]
pub enum PunchPhase {
    /// 正在 STUN 探测 + ICE 候选收集
    Probing,
    /// 已上报，等待对端候选
    WaitingPeer,
    /// ICE 连通性检测中（多候选并发）
    Punching,
    /// 成功
    Success { latency_ms: u32 },
    /// 失败
    Failed { reason: String },
}

/// 收集本端 ICE 候选地址（新版 ICE 打洞的第一步）
///
/// 返回 (candidates, ufrag, pwd, nat_type_key)
pub fn gather_ice_candidates(sock: &UdpSocket) -> (Vec<IceCandidate>, String, String, String) {
    ice::gather_all_candidates(sock)
}

/// ICE 增强打洞（新版主要接口）
///
/// 对比旧版 do_punch（单地址）：
/// - 向对端所有候选同时发包（多地址并发）
/// - 支持端口预测候选（对称 NAT 成功率大幅提升）
/// - 返回实际响应的对端地址（可能与主候选不同）
pub async fn do_ice_punch(
    sock: Arc<UdpSocket>,
    peer_candidates: Vec<IceCandidate>,
    start_at_ms: u64,
) -> PunchResult {
    if peer_candidates.is_empty() {
        return PunchResult {
            success: false,
            peer_addr: String::new(),
            latency_ms: 0,
            reason: "无对端 ICE 候选地址".to_string(),
        };
    }

    info!(
        "[ICE打洞] 开始连通性检测: {} 个对端候选",
        peer_candidates.len()
    );

    match ice::run_connectivity_checks(sock, &peer_candidates, start_at_ms).await {
        Some(result) => {
            info!(
                "[ICE打洞] ✅ 成功: {} ({:?}) RTT={}ms",
                result.peer_addr, result.ctype, result.rtt_ms
            );
            PunchResult {
                success: true,
                peer_addr: result.peer_addr.to_string(),
                latency_ms: result.rtt_ms,
                reason: String::new(),
            }
        }
        None => {
            warn!(
                "[ICE打洞] 超时，所有 {} 个候选均未响应",
                peer_candidates.len()
            );
            PunchResult {
                success: false,
                peer_addr: String::new(),
                latency_ms: 0,
                reason: format!(
                    "ICE 连通性检测超时（已尝试 {} 个候选）",
                    peer_candidates.len()
                ),
            }
        }
    }
}
