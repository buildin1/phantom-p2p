//! 桌面端的 NAT 诊断页。
//!
//! 这是 Tauri 独有的功能：多轮 STUN 采样 + 过滤行为探测，全程通过
//! `diag:progress` 事件把进度推给界面。headless 端与 Android 都没有对应界面，
//! 因此它不属于 `phantom_core::runtime` 的编排范围，留在桌面端。
//!
//! 注意这里用的是 `nat.rs` 的**五分类**（NAT1/2/3 + 递增/随机对称），
//! 与打洞决策用的 `punch.rs` 三分类是两套并存的 NAT 概念。
//! 合并计划见任务清单 G3.4。

use phantom_core::{nat, network, stun};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

/// 网络诊断信息
#[derive(Serialize, Deserialize)]
pub struct NetworkInfo {
    pub nat_type: String,
    pub nat_type_key: String,
    pub nat_difficulty: String,
    pub external_ip: String,
    pub external_port: u16,
    pub upnp: bool,
    pub upnp_port: u16,
    pub ipv6: bool,
    pub ipv6_addr: String,
    pub local_ip: String,
    pub local_port: u16,
    pub stun_mappings: Vec<String>,
    pub stun_details: Vec<StunDetail>,
    pub port_pattern: String,
    pub mapping_behavior: String,
    pub filtering_behavior: String,
    pub confidence: String,
    pub diagnostics_rounds: u8,
    pub network_priority: String,
}

#[derive(Serialize, Deserialize)]
pub struct StunDetail {
    pub server: String,
    pub mapping: String,
    pub rtt_ms: u32,
    pub socket: String,
    pub round: u8,
}

#[derive(Serialize, Clone)]
struct NetDiagProgress {
    progress: u8,
    stage: String,
    eta_seconds: u8,
}

/// 获取网络信息（NAT 类型、公网 IP、STUN、UPnP、IPv6 等）
#[tauri::command]
pub async fn get_network_info(app: AppHandle) -> Result<NetworkInfo, String> {
    const DIAG_ROUNDS: usize = 3;
    let emit_progress = |progress: u8, stage: &str, eta_seconds: u8| {
        let _ = app.emit(
            "diag:progress",
            NetDiagProgress {
                progress,
                stage: stage.to_string(),
                eta_seconds,
            },
        );
    };

    emit_progress(4, "初始化诊断环境", 15);

    let mut rounds = Vec::with_capacity(DIAG_ROUNDS);
    for idx in 0..DIAG_ROUNDS {
        let progress = 10 + (idx as u8 * 20);
        let eta = ((DIAG_ROUNDS - idx) * 4 + 3) as u8;
        emit_progress(
            progress,
            &format!("多 STUN 映射采样 第 {}/{} 轮", idx + 1, DIAG_ROUNDS),
            eta,
        );
        rounds.push(stun::query_dual_async().await);
    }

    emit_progress(72, "过滤行为探测（IP/端口限制）", 5);
    let filtering_probe = stun::detect_filtering_behavior_async().await;

    let analysis = nat::analyze_multi_round(
        &rounds,
        filtering_probe.behavior.key(),
        &format!("{} @ {}", filtering_probe.detail, filtering_probe.server),
    );

    let mut merged_a = Vec::new();
    let mut merged_b = Vec::new();
    let mut stun_details: Vec<StunDetail> = Vec::new();
    for (round_index, round) in rounds.iter().enumerate() {
        merged_a.extend(round.mappings_a.clone());
        merged_b.extend(round.mappings_b.clone());

        for sample in &round.samples_a {
            stun_details.push(StunDetail {
                server: sample.server.clone(),
                mapping: format!("{}:{}", sample.mapping.ip, sample.mapping.port),
                rtt_ms: sample.rtt_ms,
                socket: "A".to_string(),
                round: (round_index + 1) as u8,
            });
        }
        for sample in &round.samples_b {
            stun_details.push(StunDetail {
                server: sample.server.clone(),
                mapping: format!("{}:{}", sample.mapping.ip, sample.mapping.port),
                rtt_ms: sample.rtt_ms,
                socket: "B".to_string(),
                round: (round_index + 1) as u8,
            });
        }
    }

    let primary = if !merged_a.is_empty() {
        &merged_a
    } else {
        &merged_b
    };
    let (external_ip, external_port) = if let Some(first) = primary.first() {
        (first.ip.clone(), first.port)
    } else {
        ("0.0.0.0".to_string(), 0)
    };
    let local_port = rounds.first().map(|r| r.local_port_a).unwrap_or(0);

    let mut stun_mappings: Vec<String> = Vec::new();
    for detail in &stun_details {
        stun_mappings.push(format!(
            "R{}-{}→{}",
            detail.round, detail.socket, detail.mapping
        ));
    }

    emit_progress(86, "UPnP / IPv6 / 本机网卡检测", 2);
    let (upnp_result, local_net) = tokio::join!(
        network::detect_upnp(),
        tokio::task::spawn_blocking(network::detect_local_network),
    );

    let local_net = local_net.unwrap_or_else(|_| network::LocalNetworkInfo {
        local_ip: "127.0.0.1".to_string(),
        ipv6_available: false,
        ipv6_addr: String::new(),
    });

    let network_priority = if local_net.ipv6_available {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    };

    emit_progress(95, "汇总 NAT 诊断结果", 1);

    let info = NetworkInfo {
        nat_type: analysis.nat_type.display_name().to_string(),
        nat_type_key: analysis.nat_type.type_key().to_string(),
        nat_difficulty: analysis.nat_type.difficulty().to_string(),
        mapping_behavior: analysis.mapping_behavior,
        filtering_behavior: analysis.filtering_behavior,
        confidence: analysis.confidence,
        external_ip,
        external_port,
        upnp: upnp_result.available,
        upnp_port: upnp_result.external_port,
        ipv6: local_net.ipv6_available,
        ipv6_addr: local_net.ipv6_addr,
        local_ip: local_net.local_ip,
        local_port,
        stun_mappings,
        stun_details,
        port_pattern: analysis.port_pattern,
        diagnostics_rounds: DIAG_ROUNDS as u8,
        network_priority,
    };

    emit_progress(100, "诊断完成", 0);
    Ok(info)
}
