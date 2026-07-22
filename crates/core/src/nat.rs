//! NAT 类型分析 —— 双 socket RFC 5780 风格检测
//!
//! 通过两个不同源端口的 UDP socket 分别查询同一组 STUN 服务器，
//! 综合分析映射行为 (Mapping Behavior) 和过滤行为 (Filtering Behavior)：
//!
//! **映射行为（同一 socket 到不同服务器）：**
//! - EIM (端点无关映射)：端口不变 → 锥形 NAT（仅能确认 Mapping，无法仅靠普通 STUN 区分 NAT1/2/3）
//! - ADM (地址相关映射)：同地址端口相同，不同地址端口不同 → Symmetric
//! - APDM (地址+端口相关映射)：每次都不同 → Symmetric
//!
//! **交叉验证（不同 socket 到同一服务器）：**
//! - 如果映射端口不同，进一步确认对称 NAT

use crate::stun::{DualStunResult, StunMapping};

/// NAT 类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    /// 完全锥形 NAT (NAT1) — 端口固定，任何人可达
    FullCone,
    /// 受限锥形 NAT (NAT2) — 端口固定，仅已通信的 IP 可达
    RestrictedCone,
    /// 端口受限锥形 NAT (NAT3) — 端口固定，仅已通信的 IP:port 可达
    PortRestrictedCone,
    /// 对称 NAT (NAT4) - 递增分配
    SymmetricIncremental,
    /// 对称 NAT (NAT4) - 随机分配
    SymmetricRandom,
    /// 未知
    Unknown,
}

impl NatType {
    pub fn display_name(&self) -> &str {
        match self {
            NatType::FullCone => "Full Cone NAT (NAT1)",
            NatType::RestrictedCone => "Restricted Cone NAT (NAT2)",
            NatType::PortRestrictedCone => "Port Restricted Cone NAT (NAT3)",
            NatType::SymmetricIncremental => "Symmetric NAT (NAT4) - 递增",
            NatType::SymmetricRandom => "Symmetric NAT (NAT4) - 随机",
            NatType::Unknown => "未知",
        }
    }

    pub fn type_key(&self) -> &str {
        match self {
            NatType::FullCone => "full_cone",
            NatType::RestrictedCone => "restricted_cone",
            NatType::PortRestrictedCone => "port_restricted_cone",
            NatType::SymmetricIncremental => "symmetric_incremental",
            NatType::SymmetricRandom => "symmetric_random",
            NatType::Unknown => "unknown",
        }
    }

    pub fn difficulty(&self) -> &str {
        match self {
            NatType::FullCone => "★☆☆☆☆ (最容易)",
            NatType::RestrictedCone => "★★☆☆☆ (容易)",
            NatType::PortRestrictedCone => "★★★☆☆ (中等)",
            NatType::SymmetricIncremental => "★★★★☆ (较难)",
            NatType::SymmetricRandom => "★★★★★ (困难)",
            NatType::Unknown => "--",
        }
    }

    /// 是否属于锥形 NAT
    pub fn is_cone(&self) -> bool {
        matches!(
            self,
            NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone
        )
    }
}

/// 双 socket 分析结果
pub struct NatAnalysis {
    pub nat_type: NatType,
    pub port_pattern: String,
    /// 映射行为描述
    pub mapping_behavior: String,
    /// 过滤行为描述
    pub filtering_behavior: String,
    /// 诊断置信度
    pub confidence: String,
}

/// 使用双 socket 结果进行完整 NAT 分类
pub fn analyze_dual(result: &DualStunResult) -> NatAnalysis {
    analyze_multi_round(
        std::slice::from_ref(result),
        "unknown",
        "未执行过滤行为探测",
    )
}

fn format_port_brief(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "--".to_string();
    }
    let mut uniq = ports.to_vec();
    uniq.sort_unstable();
    uniq.dedup();
    if uniq.len() <= 6 {
        return uniq
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
    }
    format!(
        "{}..{} ({} 个样本)",
        uniq.first().copied().unwrap_or(0),
        uniq.last().copied().unwrap_or(0),
        uniq.len()
    )
}

fn classify_filtering(filtering_behavior_key: &str) -> (NatType, &'static str, &'static str) {
    match filtering_behavior_key {
        "endpoint_independent" => (NatType::FullCone, "EIF (端点无关过滤)", "高"),
        "address_dependent" => (NatType::RestrictedCone, "ADF (仅按 IP 限制)", "高"),
        "address_port_dependent" => (NatType::PortRestrictedCone, "APDF (IP+端口限制)", "高"),
        _ => (NatType::PortRestrictedCone, "未知 (按 NAT3 保守处理)", "中"),
    }
}

fn classify_symmetric_pattern(all_ports: &[u16]) -> (NatType, String) {
    if all_ports.len() <= 1 {
        return (NatType::SymmetricRandom, "数据不足".to_string());
    }
    let diffs: Vec<i32> = all_ports
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    let positive_small = diffs.iter().filter(|&&d| d > 0 && d <= 16).count();
    let ratio = positive_small as f32 / diffs.len() as f32;

    if ratio >= 0.68 {
        let min_d = *diffs.iter().filter(|&&d| d > 0).min().unwrap_or(&1);
        let max_d = *diffs.iter().filter(|&&d| d > 0).max().unwrap_or(&1);
        let pattern = if min_d == max_d {
            format!("递增+{}", min_d)
        } else {
            format!("递增+{}~{} (占比 {:.0}%)", min_d, max_d, ratio * 100.0)
        };
        (NatType::SymmetricIncremental, pattern)
    } else {
        (
            NatType::SymmetricRandom,
            format!("随机/跳跃 (递增占比 {:.0}%)", ratio * 100.0),
        )
    }
}

/// 多轮 NAT 分析（建议 rounds >= 3）
pub fn analyze_multi_round(
    rounds: &[DualStunResult],
    filtering_behavior_key: &str,
    filtering_detail: &str,
) -> NatAnalysis {
    if rounds.is_empty() {
        return NatAnalysis {
            nat_type: NatType::Unknown,
            port_pattern: "--".to_string(),
            mapping_behavior: "无数据".to_string(),
            filtering_behavior: "未检测".to_string(),
            confidence: "低".to_string(),
        };
    }

    let mut all_ports = Vec::new();
    let mut mapping_consistency_ok = 0usize;
    let mut mapping_consistency_total = 0usize;

    for round in rounds {
        let ports_a: Vec<u16> = round.mappings_a.iter().map(|m| m.port).collect();
        let ports_b: Vec<u16> = round.mappings_b.iter().map(|m| m.port).collect();

        if ports_a.len() >= 2 {
            mapping_consistency_total += 1;
            if ports_a.iter().all(|&p| p == ports_a[0]) {
                mapping_consistency_ok += 1;
            }
        }
        if ports_b.len() >= 2 {
            mapping_consistency_total += 1;
            if ports_b.iter().all(|&p| p == ports_b[0]) {
                mapping_consistency_ok += 1;
            }
        }

        let primary = if !round.mappings_a.is_empty() {
            &round.mappings_a
        } else {
            &round.mappings_b
        };
        all_ports.extend(primary.iter().map(|m| m.port));
    }

    let eim = mapping_consistency_total > 0 && mapping_consistency_ok == mapping_consistency_total;
    let consistency_ratio = if mapping_consistency_total == 0 {
        0.0
    } else {
        mapping_consistency_ok as f32 / mapping_consistency_total as f32
    };

    if eim {
        let (nat_type, filter_text, confidence_base) = classify_filtering(filtering_behavior_key);
        let mapping_behavior = format!(
            "EIM (端点无关映射, 稳定率 {:.0}%, 样本端口 {})",
            consistency_ratio * 100.0,
            format_port_brief(&all_ports)
        );
        return NatAnalysis {
            nat_type,
            port_pattern: "固定端口/锥形映射".to_string(),
            mapping_behavior,
            filtering_behavior: format!("{} — {}", filter_text, filtering_detail),
            confidence: confidence_base.to_string(),
        };
    }

    let (nat_type, pattern) = classify_symmetric_pattern(&all_ports);
    let mapping_behavior = format!(
        "APDM/ADM (地址或端口相关映射, 稳定率 {:.0}%, 端口样本 {})",
        consistency_ratio * 100.0,
        format_port_brief(&all_ports)
    );

    NatAnalysis {
        nat_type,
        port_pattern: pattern,
        mapping_behavior,
        filtering_behavior: "对称映射优先判定，过滤行为不再单独区分".to_string(),
        confidence: if rounds.len() >= 3 {
            "高".to_string()
        } else {
            "中".to_string()
        },
    }
}

/// 简单单 socket 分析（兼容接口，对齐 Python PortPredictor）
pub fn analyze_nat_type(mappings: &[StunMapping]) -> NatType {
    if mappings.is_empty() {
        return NatType::Unknown;
    }
    if mappings.len() == 1 {
        // 单 socket 无法检测过滤行为，按保守策略归类 NAT3
        return NatType::PortRestrictedCone;
    }
    let ports: Vec<u16> = mappings.iter().map(|m| m.port).collect();
    if ports.iter().all(|&p| p == ports[0]) {
        // 仅代表 EIM，不代表一定是 NAT1
        return NatType::PortRestrictedCone;
    }
    let diffs: Vec<i32> = ports
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    if diffs.iter().all(|&d| d > 0 && d < 10) {
        return NatType::SymmetricIncremental;
    }
    NatType::SymmetricRandom
}

/// 生成端口规律描述
pub fn describe_port_pattern(mappings: &[StunMapping]) -> String {
    if mappings.is_empty() {
        return "--".to_string();
    }
    if mappings.len() == 1 {
        return "固定端口".to_string();
    }
    let ports: Vec<u16> = mappings.iter().map(|m| m.port).collect();
    if ports.iter().all(|&p| p == ports[0]) {
        return "固定端口".to_string();
    }
    let diffs: Vec<i32> = ports
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    if diffs.iter().all(|&d| d > 0 && d < 10) {
        let min_d = diffs.iter().min().unwrap_or(&0);
        let max_d = diffs.iter().max().unwrap_or(&0);
        if min_d == max_d {
            format!("递增+{}", min_d)
        } else {
            format!("递增+{}~{}", min_d, max_d)
        }
    } else {
        "随机/跳跃".to_string()
    }
}

/// 端口预测
pub fn predict_ports(base_port: u16, nat_type: &NatType, count: usize) -> Vec<u16> {
    if nat_type.is_cone() {
        return vec![base_port];
    }
    let mut result = vec![base_port];
    for i in 1..count {
        let p = base_port as u32 + i as u32;
        if p <= 65535 {
            result.push(p as u16);
        }
    }
    result
}
