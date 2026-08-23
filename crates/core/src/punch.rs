//! 打洞引擎 —— NAT 画像探测与 8 种策略执行器
//!
//! 本模块替代旧的"一刀切扫射"实现。核心是四条原则（违反任何一条都会显著降低成功率）：
//!
//! ## 原则 A：可预测的一侧必须"安静"
//!
//! 线性对称 NAT 的出口端口是**递增计数器**——每向一个新目标发包就前进一格。
//! 旧实现向 100 个候选同时发包，等于把自己的计数器一次推进 100 格，
//! 对端基于 STUN 探测算出的预测值瞬间作废。
//! **这是与网络拥塞无关的纯自伤，候选越多破坏越彻底。**
//! 落地为 [`PunchParams::quiet`]：为真时只许向策略指定的目标发包。
//!
//! ## 原则 B：撒网成本严重不对称
//!
//! 锥形 NAT 撒 K 个目标只要 1 个 socket 发 K 个包；
//! 对称 NAT 撒 K 个目标需要 K 个 socket（每个目标一个新映射）。
//! 所以**撒网由锥形侧承担，对称侧只负责用最少 socket 稳定打固定目标**。
//! 角色分工由服务端下发，不能两侧对称执行同一套逻辑。
//!
//! ## 原则 C：撒网只是"开门"，triggered check 才是主路径
//!
//! 向猜测地址发包的真正目的不是命中，而是**在本端 NAT 上打开对这些地址的入向过滤**。
//! 对端的包一旦能进来，就能从源地址读到它的真实 `IP:port`（prflx 候选），
//! 立即定向回包即可建立双向通道。所以猜错端口不要紧，
//! **但 prflx 的处理必须走快路径，不能等下一轮定时器**。
//!
//! ## 原则 D：不可达候选必须立即淘汰
//!
//! 向对端内网地址（`192.168.*`）发包会得到 `ENETUNREACH`——本机没有到那些网段的路由。
//! 这类错误是**永久性**的，首次失败就该摘除，而不是每 20ms 重试一次直到窗口结束。

use crate::network;
use crate::stun;
use phantom_protocol::{
    CandidateType, IceCandidate, NatClass, NatProfile, NetworkType, PunchParams, PunchStrategy,
    TargetPortMode,
};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// 打洞包魔数
pub const PUNCH_MAGIC: &[u8; 4] = b"PP6P";

/// 收到 prflx 后的密集回包次数（原则 C：快路径）
const PRFLX_BURST: u32 = 5;
/// prflx 密集回包间隔
const PRFLX_BURST_INTERVAL_MS: u64 = 10;

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================
// NAT 画像探测
// ============================================================

/// 判定端口步进是否线性可预测。
///
/// 返回 `(步长, 置信度)`；步长为 0 表示不可预测。
fn analyze_step(ports: &[u16]) -> (i32, f32) {
    if ports.len() < 2 {
        return (0, 0.0);
    }
    let diffs: Vec<i32> = ports
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    // 只认"正向小步进"——负数或大跳跃说明端口被其他应用抢占或本就是随机分配
    let small: Vec<i32> = diffs
        .iter()
        .copied()
        .filter(|d| *d > 0 && *d <= 16)
        .collect();
    if small.is_empty() {
        return (0, 0.0);
    }
    let ratio = small.len() as f32 / diffs.len() as f32;
    if ratio < 0.6 {
        return (0, ratio);
    }
    // 取众数而非平均值：平均值会被个别异常步进带偏
    let mut counts: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
    for d in &small {
        *counts.entry(*d).or_insert(0) += 1;
    }
    let step = counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(d, _)| d)
        .unwrap_or(1);
    (step.clamp(1, 16), ratio)
}

/// 由 STUN 采样判定三分类（RFC 5780 映射行为测试）。
///
/// 只分三类是有意的：打洞策略只关心"端口能不能预测"，
/// 锥形 NAT 的 NAT1/2/3 子类在打洞时行为一致，细分没有收益。
///
/// 返回 `(分类, 步长, 置信度, 是否地址相关映射)`。判定按目标分组：
/// * 同一目标 IP 的不同端口之间映射就变 → 端口相关映射(APDM)，经典对称；
/// * 每个 IP 内部稳定、跨 IP 不同     → 地址相关映射(ADM)对称——CGNAT 常见，
///   **单 IP 采样在结构上永远看不见它**，会 100% 误判成锥形；
/// * 处处相同                         → 端点无关映射(EIM)，锥形。
fn classify(samples: &[stun::MappingSample]) -> (NatClass, i32, f32, bool) {
    if samples.is_empty() {
        return (NatClass::Unknown, 0, 0.0, false);
    }
    if samples.len() == 1 {
        // 单点无法判定映射行为，按最乐观的锥形处理——试一次的成本远低于直接放弃
        return (NatClass::Cone, 0, 0.0, false);
    }
    let ports: Vec<u16> = samples.iter().map(|s| s.mapping.port).collect();

    // 按目标 IP 分组（保持采样顺序，端口计数器类 NAT 的步进依赖顺序）
    let mut ip_order: Vec<IpAddr> = Vec::new();
    let mut by_ip: std::collections::HashMap<IpAddr, Vec<u16>> = std::collections::HashMap::new();
    for s in samples {
        let ip = s.target.ip();
        if !by_ip.contains_key(&ip) {
            ip_order.push(ip);
        }
        by_ip.entry(ip).or_default().push(s.mapping.port);
    }

    let apdm = by_ip
        .values()
        .any(|g| g.len() >= 2 && g.iter().any(|p| *p != g[0]));
    if apdm {
        let (step, conf) = analyze_step(&ports);
        return if step > 0 {
            (NatClass::LinearSymmetric, step, conf, false)
        } else {
            (NatClass::RandomSymmetric, 0, conf, false)
        };
    }

    // 每个 IP 内部映射稳定；比较跨 IP 的代表端口
    let ip_ports: Vec<u16> = ip_order.iter().map(|ip| by_ip[ip][0]).collect();
    if ip_ports.iter().any(|p| *p != ip_ports[0]) {
        // ADM：映射只随目标 IP 变化。步进按"每换一个 IP"计算——
        // 对同一 IP 的重复采样不推进计数器，混进全序列会稀释步进比例。
        let (step, conf) = analyze_step(&ip_ports);
        return if step > 0 {
            (NatClass::LinearSymmetric, step, conf, true)
        } else {
            (NatClass::RandomSymmetric, 0, conf, true)
        };
    }

    (NatClass::Cone, 0, 1.0, false)
}

/// 细分类展示名（仅用于展示与遥测，不参与策略选择）
fn detail_name(class: NatClass, step: i32, adm: bool) -> String {
    match class {
        NatClass::Cone => "cone".to_string(),
        NatClass::LinearSymmetric if adm => format!("symmetric_adm_step{}", step),
        NatClass::LinearSymmetric => format!("symmetric_incremental_step{}", step),
        NatClass::RandomSymmetric if adm => "symmetric_adm_random".to_string(),
        NatClass::RandomSymmetric => "symmetric_random".to_string(),
        NatClass::Unknown => "unknown".to_string(),
    }
}

/// 探测结果：NAT 画像 + 基础候选
pub struct ProbeResult {
    pub profile: NatProfile,
    pub base_candidates: Vec<IceCandidate>,
    /// 探测耗时（毫秒），用于遥测 `gather_ms`
    pub gather_ms: u32,
}

/// 校验对端在 NatProfile 中声明的临时公钥。
///
/// 不验签就直接做 DH 是不够的：信令服务器同时也是中继运营方，
/// 它可以替换双方的临时公钥，各自与自己做 DH，从而在中间解密全部流量。
/// 用长期身份密钥签名临时公钥能挡住这一手。
///
/// **残留信任**：本函数只能证明"临时公钥确实由持有该身份私钥者签发"，
/// 无法证明该身份就是你想连的那个人——身份公钥本身也是经服务端转发的。
/// 完整防护需要带外的身份确认（TOFU 或可信目录），不在本层解决。
pub fn verify_peer_ephemeral(profile: &NatProfile) -> Result<[u8; 32], String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&profile.identity_public)
        .map_err(|_| "对端身份公钥非法".to_string())?;
    let sig = Signature::from_bytes(&profile.eph_signature);
    vk.verify(&profile.eph_public, &sig)
        .map_err(|_| "对端临时公钥签名验证失败（可能存在中间人）".to_string())?;
    Ok(profile.eph_public)
}

/// 探测 NAT 画像并收集基础候选（阶段一）。
///
/// **只产出 host + srflx 候选**——预测/撒网候选属于阶段二，
/// 必须等服务端下发策略后才能生成（那时才知道对端的 NAT 类型）。
///
/// `stun_servers` 由服务端下发，客户端不内置任何地址。
pub fn probe(
    sock: &UdpSocket,
    stun_servers: &[(String, u16)],
    signal_rtt_ms: u32,
    identity: &crate::identity::Identity,
    eph_public: [u8; 32],
) -> ProbeResult {
    let started = Instant::now();

    let samples = stun::sample_mappings_on(sock, stun_servers);
    let (class, step, step_confidence, adm) = classify(&samples);

    // 判定质量自检——"日志说 cone_to_cone 却打洞失败"的两大来源都在采样环节，
    // 必须在第一现场把话说清楚，不能等到失败之后无从追溯。
    if samples.len() == 1 {
        warn!(
            "[打洞] STUN 仅 1 个样本（{} 台里只有 1 台应答），无法判定映射行为，\
             乐观按锥形处理；本次 NAT 分类不可信，打洞失败时优先怀疑这里",
            stun_servers.len()
        );
    }
    let distinct_ips: std::collections::HashSet<IpAddr> =
        samples.iter().map(|s| s.target.ip()).collect();
    if class == NatClass::Cone && samples.len() >= 2 && distinct_ips.len() < 2 {
        warn!(
            "[打洞] 采样只覆盖到 1 个目标 IP（{} 个样本，OTHER-ADDRESS 也没发现第二个 IP），\
             地址相关映射型对称 NAT 仍会被误判为锥形；建议在服务端 [stun].fallback_servers \
             配置至少一台**不同 IP** 且支持 RFC 5780 的 STUN（可写裸主机名，默认端口 3478）",
            samples.len()
        );
    }

    // 过滤行为探测（RFC 5780 Test II/III）：只向已采样过的目标发请求，
    // 不新增出网目标、不推进对称 NAT 的端口计数器。优先选自带换 IP 端点
    // （OTHER-ADDRESS 是另一个 IP）的服务器做主目标，Test II 才做得了。
    let filtering = if samples.is_empty() {
        None
    } else {
        let full_5780 = samples.iter().find(|s| {
            s.alt_server
                .map(|a| a.ip() != s.target.ip())
                .unwrap_or(false)
        });
        let (primary, alt) = match full_5780 {
            Some(s) => (s.target, s.alt_server),
            None => (samples[0].target, None),
        };
        let f = stun::probe_filtering_on(sock, primary, alt);
        info!(
            "[打洞] 入向过滤行为: {}{}",
            f.behavior.display_name(),
            if f.certain {
                ""
            } else {
                "（无换 IP 端点，只能给上界）"
            }
        );
        Some(f)
    };

    let public_ip = samples.last().map(|s| s.mapping.ip.clone());
    let base_port = samples.last().map(|s| s.mapping.port).unwrap_or(0);
    let sample_ports: Vec<u16> = samples.iter().map(|s| s.mapping.port).collect();

    let (has_ipv6, ipv6_addrs) = probe_ipv6();

    let mut base_candidates = gather_host_candidates(sock, &ipv6_addrs);
    base_candidates.extend(srflx_candidates(&samples));
    dedup_and_sort(&mut base_candidates);

    // detail 尾部带上过滤行为（=确定 / ~上界），供对端日志与遥测排障；
    // 字段是自由文本，旧版本对端原样展示，不存在兼容问题
    let mut detail = detail_name(class, step, adm);
    if let Some(f) = &filtering {
        let tag = match f.behavior {
            stun::FilteringBehavior::EndpointIndependent => "eif",
            stun::FilteringBehavior::AddressDependent => "adf",
            stun::FilteringBehavior::AddressPortDependent => "apdf",
            stun::FilteringBehavior::Unknown => "",
        };
        if !tag.is_empty() {
            detail.push_str(if f.certain { ",filter=" } else { ",filter~" });
            detail.push_str(tag);
        }
    }

    let profile = NatProfile {
        class,
        detail,
        base_port,
        step,
        step_confidence,
        sample_ports,
        public_ip,
        has_ipv6,
        ipv6_addrs,
        network_type: detect_network_type(),
        signal_rtt_ms,
        eph_public,
        // 用长期身份密钥为临时公钥背书，挡住信令服务器的中间人替换
        eph_signature: identity.sign(&eph_public),
        identity_public: identity.public_key_bytes(),
    };

    let gather_ms = started.elapsed().as_millis() as u32;
    info!(
        "[打洞] NAT 画像: class={:?} step={} 置信度={:.0}% base_port={} ipv6={} 候选={} 个 耗时={}ms",
        profile.class,
        profile.step,
        profile.step_confidence * 100.0,
        profile.base_port,
        profile.has_ipv6,
        base_candidates.len(),
        gather_ms
    );

    ProbeResult {
        profile,
        base_candidates,
        gather_ms,
    }
}

/// 检测可用的全局 IPv6。
///
/// 关键：**不只看有没有地址，还要验证能不能出网**。
/// 很多环境有全局 IPv6 地址但实际不可达，误判会让快速通道白白浪费 12 秒窗口。
fn probe_ipv6() -> (bool, Vec<String>) {
    let addrs = network::global_ipv6_addrs();
    if addrs.is_empty() {
        return (false, addrs);
    }
    // 用 UDP connect 探测路由可达性（不实际发包）
    let reachable = std::net::UdpSocket::bind("[::]:0")
        .ok()
        .and_then(|s| {
            s.connect("[2400:3200::1]:53")
                .or_else(|_| s.connect("[2001:4860:4860::8888]:53"))
                .ok()?;
            s.local_addr().ok()
        })
        .map(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())
        .unwrap_or(false);
    if !reachable {
        debug!("[打洞] 有全局 IPv6 地址但路由不可达，不启用 IPv6 快速通道");
    }
    (reachable, addrs)
}

fn detect_network_type() -> NetworkType {
    // 精确的接入类型识别依赖各平台 API，此处给出保守默认值。
    // 该字段仅用于遥测维度切分，不参与策略选择。
    NetworkType::Unknown
}

fn gather_host_candidates(sock: &UdpSocket, ipv6_addrs: &[String]) -> Vec<IceCandidate> {
    let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut out = Vec::new();

    for (idx, ip) in network::local_ipv4_addrs().into_iter().enumerate() {
        out.push(IceCandidate {
            ip,
            port,
            ctype: CandidateType::Host,
            priority: crate::ice::ice_priority(
                CandidateType::Host,
                255u16.saturating_sub(idx as u16),
            ),
            foundation: format!("h{}", idx),
        });
    }
    // IPv6 无 NAT，直连成功率接近 100%，优先级应高于所有 IPv4 候选
    for (idx, ip) in ipv6_addrs.iter().enumerate() {
        out.push(IceCandidate {
            ip: ip.clone(),
            port,
            ctype: CandidateType::Host,
            priority: crate::ice::ice_priority_ipv6_host().saturating_sub(idx as u32),
            foundation: format!("h6_{}", idx),
        });
    }
    out
}

fn srflx_candidates(samples: &[stun::MappingSample]) -> Vec<IceCandidate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (idx, s) in samples.iter().enumerate() {
        let m = &s.mapping;
        if !seen.insert((m.ip.clone(), m.port)) {
            continue;
        }
        out.push(IceCandidate {
            ip: m.ip.clone(),
            port: m.port,
            ctype: CandidateType::ServerReflexive,
            priority: crate::ice::ice_priority(
                CandidateType::ServerReflexive,
                255u16.saturating_sub(idx as u16),
            ),
            foundation: format!("s{}", idx),
        });
    }
    out
}

fn dedup_and_sort(cands: &mut Vec<IceCandidate>) {
    let mut seen = HashSet::new();
    cands.retain(|c| seen.insert((c.ip.clone(), c.port)));
    cands.sort_by(|a, b| b.priority.cmp(&a.priority));
}

// ============================================================
// 阶段二：按策略生成候选
// ============================================================

/// 按下发的策略生成本端的"策略候选"。
///
/// 返回 `(新建的 socket 列表, 需要上报给对端的候选)`。
///
/// - `local_socket_count > 1` 时会新建对应数量的 socket，
///   并对每个 socket 做一次 STUN 探测拿到其公网映射，回报给对端；
/// - `local_socket_count <= 1` 时复用探测 socket，不产生新候选。
pub fn build_strategy_candidates(
    params: PunchParams,
    stun_servers: &[(String, u16)],
) -> (Vec<Arc<UdpSocket>>, Vec<IceCandidate>) {
    let mut socks = Vec::new();
    let mut cands = Vec::new();

    if params.local_socket_count <= 1 {
        return (socks, cands);
    }

    for i in 0..params.local_socket_count {
        let Ok(s) = network::bind_dual_stack_udp(0) else {
            warn!("[打洞] 第 {} 个 socket 创建失败，按已创建的数量继续", i);
            break;
        };
        // 每个新 socket 都要探一次映射，否则对端不知道该往哪打
        if let Some(m) = stun::query_first_on(&s, stun_servers) {
            cands.push(IceCandidate {
                ip: m.ip,
                port: m.port,
                ctype: CandidateType::Strategy,
                priority: crate::ice::ice_priority(
                    CandidateType::Strategy,
                    255u16.saturating_sub(i),
                ),
                foundation: format!("ms{}", i),
            });
        }
        socks.push(Arc::new(s));
    }

    info!(
        "[打洞] 策略候选：新建 {} 个 socket，探测到 {} 个映射",
        socks.len(),
        cands.len()
    );
    (socks, cands)
}

/// 按策略生成**目标地址表**（要打的对端地址）。
///
/// 这是原则 B 的落地点：撒网发生在目标端口维度（锥形侧便宜），
/// 而非源端口维度（对称侧昂贵）。
pub fn build_targets(
    params: PunchParams,
    peer_profile: &NatProfile,
    peer_candidates: &[IceCandidate],
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    // 策略指定的对端主公网地址（quiet 侧唯一允许打的公网 IPv4 目标）。
    let base_public: Option<SocketAddr> = peer_profile
        .public_ip
        .as_ref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, peer_profile.base_port));

    // 对端明确上报的候选永远要打——它们是最可靠的目标。
    //
    // 例外是 quiet 策略（原则 A 的落地点，此前 quiet 只被打印、从未被执行）：
    // 本端是线性对称 NAT 时，每向一个**新的公网 IPv4 目标**发包，出口端口
    // 计数器就前进一格，对端基于探测算出的端口预测立刻作废——候选越多，
    // 自伤越彻底。所以 quiet 侧对公网 IPv4 只打策略指定的那一个固定目标；
    // 内网候选（不经过本端 NAT，不消耗计数器）和 IPv6（无 NAT 端口映射）
    // 不受限制。
    for c in peer_candidates {
        if let Ok(ip) = c.ip.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, c.port);
            if params.quiet {
                if let IpAddr::V4(v4) = ip {
                    let is_local = v4.is_private() || v4.is_loopback() || v4.is_link_local();
                    if !is_local && Some(addr) != base_public {
                        debug!("[打洞] quiet：跳过计划外公网候选 {}", addr);
                        continue;
                    }
                }
            }
            if seen.insert(addr) {
                out.push(addr);
            }
        }
    }

    // 再按策略补充预测/撒网目标
    let Some(peer_ip) = peer_profile
        .public_ip
        .as_ref()
        .and_then(|s| s.parse::<IpAddr>().ok())
    else {
        return out;
    };

    match params.target_port_mode {
        TargetPortMode::Fixed => {
            // 兜底：策略指定的主公网地址必须在目标表里。正常情况下它就在
            // 对端上报的 srflx 候选中，但 quiet 过滤或候选缺失时不能漏掉它。
            if let Some(addr) = base_public {
                if seen.insert(addr) {
                    out.push(addr);
                }
            }
        }
        TargetPortMode::LinearPredict => {
            // 对端每向一个新目标发包端口就前进 step，
            // 向前预测若干格覆盖它打给我们时会用到的端口
            let step = if peer_profile.step > 0 {
                peer_profile.step
            } else {
                1
            };
            for k in 1..=params.target_port_count as i32 {
                let p = peer_profile.base_port as i32 + step * k;
                if (1..=65535).contains(&p) {
                    let addr = SocketAddr::new(peer_ip, p as u16);
                    if seen.insert(addr) {
                        out.push(addr);
                    }
                }
            }
        }
        TargetPortMode::RandomSpray => {
            // 随机对称端口不可预测：以历史采样为中心向两侧铺开，
            // 再补充全局随机采样提高生日悖论的命中面
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let half = (params.target_port_count / 2).max(1);
            for i in 1..=half as i32 {
                for p in [
                    peer_profile.base_port as i32 + i,
                    peer_profile.base_port as i32 - i,
                ] {
                    if (1024..=65535).contains(&p) {
                        let addr = SocketAddr::new(peer_ip, p as u16);
                        if seen.insert(addr) {
                            out.push(addr);
                        }
                    }
                }
            }
            while out.len() < params.target_port_count as usize + peer_candidates.len() {
                let p: u16 = rng.gen_range(1024..=65535);
                let addr = SocketAddr::new(peer_ip, p);
                if seen.insert(addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

// ============================================================
// 阶段三：执行打洞
// ============================================================

/// 打洞成功的结果
#[derive(Debug, Clone)]
pub struct PunchSuccess {
    /// 实际连通的对端地址
    pub peer_addr: SocketAddr,
    /// 命中的本端 socket 在列表中的下标（0 = 主探测 socket）
    pub socket_index: usize,
    /// 实测 RTT（由回包携带的时间戳算得，不是"首次响应耗时"）
    pub rtt_ms: u32,
    /// 命中的候选类型
    pub ctype: CandidateType,
}

/// 一个待打的目标及其失败状态
struct Target {
    addr: SocketAddr,
    ctype: CandidateType,
    /// 永久失败后摘除（原则 D）
    dead: bool,
}

/// 判定 socket 错误是否为**永久性**不可达。
///
/// `ENETUNREACH` / `EHOSTUNREACH` / `EADDRNOTAVAIL` 说明本机根本没有到该网段的路由
/// （典型场景：对端上报了 `192.168.x.x` 内网候选）。
/// 这类错误重试没有任何意义，必须首次即摘除——
/// 实测日志里这一项曾产生 3192 次无效重试。
fn is_permanent_failure(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable
    )
}

/// 执行打洞。
///
/// * `sockets` —— 本端所有可用 socket；`sockets[0]` 是主探测 socket，
///   其余是策略新建的（原则 B：对称侧靠 socket 数量堆概率）。
/// * `targets` —— 由 [`build_targets`] 生成的目标地址表。
/// * `start_delay_ms` —— 服务端为本端算好的起跑等待时长（已扣除本端单程延迟）。
///
/// 返回 `(成功结果, 实际等待的毫秒数)`，后者用于遥测核对同步质量。
pub async fn execute(
    sockets: Vec<Arc<UdpSocket>>,
    targets: Vec<SocketAddr>,
    params: PunchParams,
    start_delay_ms: u32,
) -> (Option<PunchSuccess>, i32) {
    if sockets.is_empty() || targets.is_empty() {
        warn!("[打洞] socket 或目标为空，放弃");
        return (None, 0);
    }

    for s in &sockets {
        let _ = s.set_nonblocking(true);
        // 显式放大接收缓冲区：撒网场景下瞬时到达速率很高，
        // 默认 64KB 会在不到一秒内被填满，真正的应答包就此丢失。
        network::tune_udp_socket(s);
    }

    // 打洞 socket 是 AF_INET6 双栈的，**不能直接接收 IPv4 的 sockaddr_in**——
    // 传原始 IPv4 地址会让 send_to 返回 WSAEFAULT(10014) 而不是发出去。
    // 必须先转成 IPv4-mapped（::ffff:a.b.c.d）。
    // 漏掉这一步会让所有 IPv4 目标 100% 发送失败，而 IPv6 目标照常工作，
    // 于是只有纯 IPv4 环境会静默退化到中继。
    let reference = &sockets[0];
    let mut targets: Vec<Target> = targets
        .into_iter()
        .map(|addr| Target {
            addr: network::compatible_socket_addr(reference, addr),
            ctype: CandidateType::Strategy,
            dead: false,
        })
        .collect();

    // 等待服务端为本端计算好的起跑时长。
    // 用相对延迟而非绝对时间戳：后者要求两端与服务端墙钟一致，
    // 客户端时钟偏差会等量地破坏同步（实测偏差曾达 3.5 秒）。
    let waited = start_delay_ms.min(5_000);
    if waited > 0 {
        tokio::time::sleep(Duration::from_millis(waited as u64)).await;
    }

    info!(
        "[打洞] 开始：{} 个 socket × {} 个目标, 间隔 {}ms, 窗口 {}ms, quiet={}",
        sockets.len(),
        targets.len(),
        params.send_interval_ms,
        params.window_ms,
        params.quiet
    );

    let start = Instant::now();
    let deadline = start + Duration::from_millis(params.window_ms as u64);
    let mut last_send = Instant::now()
        .checked_sub(Duration::from_millis(params.send_interval_ms as u64))
        .unwrap_or_else(Instant::now);
    let mut buf = [0u8; 256];
    // prflx 学到的对端真实地址（原则 C 的主路径）
    let mut prflx: HashSet<SocketAddr> = HashSet::new();

    loop {
        if Instant::now() >= deadline {
            let alive = targets.iter().filter(|t| !t.dead).count();
            warn!(
                "[打洞] 窗口 {}ms 结束仍未连通（存活目标 {}/{}）",
                params.window_ms,
                alive,
                targets.len()
            );
            return (None, waited as i32);
        }

        // ── 发送 ────────────────────────────────────────────────
        if last_send.elapsed() >= Duration::from_millis(params.send_interval_ms as u64) {
            let packet = make_packet();
            for (si, sock) in sockets.iter().enumerate() {
                for t in targets.iter_mut() {
                    if t.dead {
                        continue;
                    }
                    match sock.send_to(&packet, t.addr) {
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) if is_permanent_failure(&e) => {
                            // 原则 D：永久失败首次即摘除，不再浪费后续每一轮
                            debug!("[打洞] 目标 {} 永久不可达（{}），摘除", t.addr, e);
                            t.dead = true;
                        }
                        Err(e) => {
                            debug!("[打洞] socket{} → {} 发送失败: {}", si, t.addr, e);
                        }
                    }
                }
            }
            last_send = Instant::now();
        }

        // ── 接收：每轮 drain 干净 ──────────────────────────────
        // 旧实现每轮只收一个包再 sleep 5ms（约 200 包/秒），
        // 在撒网场景下远低于到达速率，缓冲区溢出后真正的应答会被丢弃。
        let mut got_any = false;
        for (si, sock) in sockets.iter().enumerate() {
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        got_any = true;
                        if n < 12 || &buf[..4] != PUNCH_MAGIC {
                            continue;
                        }
                        let sent_at = u64::from_be_bytes([
                            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
                        ]);

                        // 原则 C：来自未知地址 = 学到了对端的真实出口，立即快路径回包
                        if !targets.iter().any(|t| t.addr == from) && prflx.insert(from) {
                            info!("[打洞] 🔀 发现对端真实地址 {}（prflx），立即定向回包", from);
                            targets.push(Target {
                                addr: from,
                                ctype: CandidateType::ServerReflexive,
                                dead: false,
                            });
                        }

                        // 立即回第一份，不等下一轮定时器；突发的后续几份丢给
                        // 独立任务错峰发送。旧实现在接收循环里就地 sleep，每收
                        // 一个包主循环就停摆 PRFLX_BURST×间隔 ≈ 50ms——期间既不
                        // 发常规探测也不收包，撒网场景下回包越多、20ms 的发包
                        // 节奏被打得越乱，"密集回包"反而成了拖垮打洞的一环。
                        let ack = make_ack(sent_at);
                        let _ = sock.send_to(&ack, from);
                        if PRFLX_BURST > 1 {
                            let burst_sock = sock.clone();
                            let burst_ack = ack.clone();
                            tokio::spawn(async move {
                                for _ in 1..PRFLX_BURST {
                                    tokio::time::sleep(Duration::from_millis(
                                        PRFLX_BURST_INTERVAL_MS,
                                    ))
                                    .await;
                                    let _ = burst_sock.send_to(&burst_ack, from);
                                }
                            });
                        }

                        // 收到对方回显我们时间戳的包 = 双向确认完成
                        if is_ack(&buf[..n]) {
                            let rtt = now_ms().saturating_sub(sent_at) as u32;
                            let ctype = targets
                                .iter()
                                .find(|t| t.addr == from)
                                .map(|t| t.ctype)
                                .unwrap_or(CandidateType::ServerReflexive);
                            info!("[打洞] ✅ 双向连通 {} (socket{}, RTT {}ms)", from, si, rtt);
                            return (
                                Some(PunchSuccess {
                                    peer_addr: from,
                                    socket_index: si,
                                    rtt_ms: rtt,
                                    ctype,
                                }),
                                waited as i32,
                            );
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        if !got_any {
            // 没有可读数据时才让出 CPU，避免空转
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

/// 探测包：MAGIC + 发送时刻（用于对端回显算 RTT）
fn make_packet() -> Vec<u8> {
    let mut p = Vec::with_capacity(13);
    p.extend_from_slice(PUNCH_MAGIC);
    p.extend_from_slice(&now_ms().to_be_bytes());
    p.push(0); // 0 = 探测
    p
}

/// 应答包：回显对端的发送时刻，使对端能算出真实 RTT
fn make_ack(peer_sent_at: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(13);
    p.extend_from_slice(PUNCH_MAGIC);
    p.extend_from_slice(&peer_sent_at.to_be_bytes());
    p.push(1); // 1 = 应答
    p
}

fn is_ack(pkt: &[u8]) -> bool {
    pkt.len() >= 13 && pkt[12] == 1
}

/// 策略是否根本不需要打洞（直接走中继）
pub fn is_relay_only(strategy: PunchStrategy) -> bool {
    matches!(strategy, PunchStrategy::RelayOnly)
}

// ============================================================
// 客户端三阶段会话
// ============================================================

/// 一次 Host↔Guest 打洞的客户端侧状态机。
///
/// 放在 core 而不是各客户端里，是为了让 `src-tauri` 与 `src-web`
/// 共用同一份时序实现——这套流程有严格的阶段依赖，
/// 两处各写一遍必然走样。
pub struct Session {
    /// `[0]` 是主探测 socket，其余是阶段二按策略新建的
    sockets: Vec<Arc<UdpSocket>>,
    profile: Option<NatProfile>,
    gather_ms: u32,
    plan: Option<PlanState>,
    /// 本次会话的临时 X25519 密钥对，DH 后即消耗
    ephemeral: Option<crate::crypto::EphemeralKeypair>,
    /// DH 派生出的 overlay 数据面密钥
    crypto: Option<Arc<crate::crypto::SessionCrypto>>,
    /// 从发起到最终完成的计时起点
    started: Instant,
}

struct PlanState {
    attempt_id: String,
    strategy: PunchStrategy,
    params: PunchParams,
    peer_profile: NatProfile,
}

/// 打洞结束后的完整结果（含可直接上报的遥测记录）
pub struct SessionOutcome {
    pub success: Option<PunchSuccess>,
    /// 命中的 socket，可直接交给 quinn 复用（打洞打通的正是这个映射）
    pub socket: Option<Arc<UdpSocket>>,
    /// overlay 数据面密钥，交给 TunBridge 使用
    pub crypto: Option<Arc<crate::crypto::SessionCrypto>>,
    pub record: phantom_protocol::PunchRecord,
}

impl Session {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
            profile: None,
            gather_ms: 0,
            plan: None,
            ephemeral: None,
            crypto: None,
            started: Instant::now(),
        }
    }

    /// DH 派生出的 overlay 会话密钥；阶段二完成后可用。
    ///
    /// 隧道层必须用它——中继模式下 QUIC 只做逐跳加密，
    /// 不套这一层的话中继能看到全部明文。
    pub fn crypto(&self) -> Option<Arc<crate::crypto::SessionCrypto>> {
        self.crypto.clone()
    }

    /// 主 socket（探测与大多数策略都用它）
    pub fn primary_socket(&self) -> Option<Arc<UdpSocket>> {
        self.sockets.first().cloned()
    }

    /// **阶段一**：绑定主 socket、探测 NAT 画像、收集基础候选。
    pub fn probe(
        &mut self,
        stun_servers: &[(String, u16)],
        signal_rtt_ms: u32,
        identity: &crate::identity::Identity,
    ) -> Result<(NatProfile, Vec<IceCandidate>), String> {
        let sock =
            network::bind_dual_stack_udp(0).map_err(|e| format!("绑定打洞 socket 失败: {e}"))?;
        // 临时密钥随画像一起发给对端；画像本就双向转发，是天然的交换载体
        let eph = crate::crypto::EphemeralKeypair::generate();
        let result = probe(
            &sock,
            stun_servers,
            signal_rtt_ms,
            identity,
            eph.public_bytes(),
        );
        self.ephemeral = Some(eph);
        self.sockets = vec![Arc::new(sock)];
        self.gather_ms = result.gather_ms;
        self.profile = Some(result.profile.clone());
        Ok((result.profile, result.base_candidates))
    }

    /// **阶段二**：收到服务端下发的计划。
    ///
    /// 返回需要补报给对端的策略候选；无需二次交换时返回空 Vec。
    pub fn on_plan(
        &mut self,
        attempt_id: String,
        strategy: PunchStrategy,
        params: PunchParams,
        peer_profile: NatProfile,
        stun_servers: &[(String, u16)],
        is_initiator: bool,
    ) -> Vec<IceCandidate> {
        // 必须把双方的真实分类一并打出来：策略名会撒谎——任一侧探测失败
        // （Unknown）时策略同样叫 cone_to_cone，只看策略名会得出"双方都是
        // 锥形怎么还失败"的错误结论。detail 里带着 unknown/step 等第一手判定。
        info!(
            "[打洞] 收到计划: 策略={} 本端NAT={}({}, 置信度{:.2}) 对端NAT={}({}, base_port={}) socket数={} 目标模式={:?} 宽度={} quiet={}",
            strategy.as_str(),
            self.profile
                .as_ref()
                .map(|p| format!("{:?}", p.class))
                .unwrap_or_else(|| "未探测".into()),
            self.profile
                .as_ref()
                .map(|p| p.detail.clone())
                .unwrap_or_default(),
            self.profile
                .as_ref()
                .map(|p| p.step_confidence)
                .unwrap_or(0.0),
            format!("{:?}", peer_profile.class),
            peer_profile.detail,
            peer_profile.base_port,
            params.local_socket_count,
            params.target_port_mode,
            params.target_port_count,
            params.quiet
        );

        // 验签后做 DH，派生 overlay 数据面密钥。
        // is_initiator 必须两侧相反（约定 Host 恒为 true），
        // 否则双方会用同一把密钥发送，造成 nonce 复用。
        match (self.ephemeral.take(), verify_peer_ephemeral(&peer_profile)) {
            (Some(eph), Ok(peer_pub)) => {
                let salt = attempt_id.as_bytes();
                self.crypto = Some(Arc::new(eph.derive(&peer_pub, salt, is_initiator)));
                info!("[打洞] overlay 会话密钥已派生 (initiator={})", is_initiator);
            }
            (_, Err(e)) => {
                warn!("[打洞] {}；本次连接将无法建立加密数据面", e);
            }
            (None, _) => {
                warn!("[打洞] 临时密钥缺失（重复的计划下发？），跳过密钥派生");
            }
        }

        self.plan = Some(PlanState {
            attempt_id,
            strategy,
            params,
            peer_profile,
        });

        let (mut extra_socks, cands) = build_strategy_candidates(params, stun_servers);
        self.sockets.append(&mut extra_socks);
        cands
    }

    /// **阶段三**：按计划执行打洞，返回结果与可直接上报的遥测记录。
    pub async fn run(
        &mut self,
        peer_candidates: Vec<IceCandidate>,
        start_delay_ms: u32,
        ctx: RecordContext,
    ) -> SessionOutcome {
        let Some(plan) = self.plan.take() else {
            return self.fail_record(
                ctx,
                phantom_protocol::PunchOutcome::StrategyUnsupported,
                Some("未收到打洞计划".into()),
                0,
                0,
            );
        };

        if is_relay_only(plan.strategy) {
            return self.fail_record(
                ctx,
                phantom_protocol::PunchOutcome::StrategyUnsupported,
                Some("策略判定为不可打洞".into()),
                0,
                0,
            );
        }

        let remote_count = peer_candidates.len() as u16;
        let targets = build_targets(plan.params, &plan.peer_profile, &peer_candidates);
        let punch_started = Instant::now();
        let (success, skew) =
            execute(self.sockets.clone(), targets, plan.params, start_delay_ms).await;
        let establish_ms = punch_started.elapsed().as_millis() as u32;

        let profile = self.profile.clone().unwrap_or_else(placeholder_profile);
        let outcome = if success.is_some() {
            phantom_protocol::PunchOutcome::P2pSuccess
        } else if profile.public_ip.is_none() {
            // 连 srflx 都没拿到，根因是 STUN 而不是打洞本身
            phantom_protocol::PunchOutcome::NoSrflx
        } else {
            phantom_protocol::PunchOutcome::PunchTimeout
        };

        let socket = success
            .as_ref()
            .and_then(|s| self.sockets.get(s.socket_index).cloned());

        let record = phantom_protocol::PunchRecord {
            attempt_id: plan.attempt_id,
            room_code: ctx.room_code,
            peer_session_id: ctx.peer_session_id,
            is_host: ctx.is_host,
            local_nat_class: profile.class,
            local_nat_detail: profile.detail.clone(),
            remote_nat_class: plan.peer_profile.class,
            local_network_type: profile.network_type,
            local_public_ip: profile.public_ip.clone(),
            local_has_ipv6: profile.has_ipv6,
            remote_has_ipv6: plan.peer_profile.has_ipv6,
            strategy: plan.strategy,
            params: plan.params,
            local_candidate_count: self.sockets.len() as u16,
            remote_candidate_count: remote_count,
            outcome,
            selected_candidate_type: success.as_ref().map(|s| s.ctype),
            failure_detail: None,
            gather_ms: self.gather_ms,
            signal_rtt_ms: profile.signal_rtt_ms,
            punch_start_skew_ms: skew,
            p2p_establish_ms: establish_ms,
            total_ms: self.started.elapsed().as_millis() as u32,
            final_rtt_ms: success.as_ref().map(|s| s.rtt_ms).unwrap_or(0),
            loss_rate: 0.0,
            client_version: ctx.client_version,
            os: ctx.os,
        };

        SessionOutcome {
            success,
            socket,
            crypto: self.crypto.clone(),
            record,
        }
    }

    fn fail_record(
        &self,
        ctx: RecordContext,
        outcome: phantom_protocol::PunchOutcome,
        detail: Option<String>,
        establish_ms: u32,
        skew: i32,
    ) -> SessionOutcome {
        let profile = self.profile.clone().unwrap_or_else(placeholder_profile);
        SessionOutcome {
            success: None,
            socket: None,
            crypto: None,
            record: phantom_protocol::PunchRecord {
                attempt_id: String::new(),
                room_code: ctx.room_code,
                peer_session_id: ctx.peer_session_id,
                is_host: ctx.is_host,
                local_nat_class: profile.class,
                local_nat_detail: profile.detail.clone(),
                remote_nat_class: NatClass::Unknown,
                local_network_type: profile.network_type,
                local_public_ip: profile.public_ip.clone(),
                local_has_ipv6: profile.has_ipv6,
                remote_has_ipv6: false,
                strategy: PunchStrategy::RelayOnly,
                params: PunchParams::for_strategy(PunchStrategy::RelayOnly),
                local_candidate_count: 0,
                remote_candidate_count: 0,
                outcome,
                selected_candidate_type: None,
                failure_detail: detail,
                gather_ms: self.gather_ms,
                signal_rtt_ms: profile.signal_rtt_ms,
                punch_start_skew_ms: skew,
                p2p_establish_ms: establish_ms,
                total_ms: self.started.elapsed().as_millis() as u32,
                final_rtt_ms: 0,
                loss_rate: 0.0,
                client_version: ctx.client_version,
                os: ctx.os,
            },
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成遥测记录所需的上下文（客户端自己知道，引擎不关心）
#[derive(Clone)]
pub struct RecordContext {
    pub room_code: String,
    pub peer_session_id: String,
    pub is_host: bool,
    pub client_version: String,
    pub os: String,
}

impl RecordContext {
    pub fn new(room_code: String, peer_session_id: String, is_host: bool) -> Self {
        Self {
            room_code,
            peer_session_id,
            is_host,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
        }
    }
}

/// 仅用于"探测都没走到"的失败记录；不含任何真实密钥材料
fn placeholder_profile() -> NatProfile {
    NatProfile {
        eph_public: [0u8; 32],
        eph_signature: [0u8; 64],
        identity_public: [0u8; 32],
        class: NatClass::Unknown,
        detail: "unknown".into(),
        base_port: 0,
        step: 0,
        step_confidence: 0.0,
        sample_ports: Vec::new(),
        public_ip: None,
        has_ipv6: false,
        ipv6_addrs: Vec::new(),
        network_type: NetworkType::Unknown,
        signal_rtt_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::StunMapping;

    /// target 用 "IP:port" 字面量；判定 ADM 的关键维度就是目标 IP
    fn sample(target: &str, mapped_port: u16) -> stun::MappingSample {
        stun::MappingSample {
            server: target.to_string(),
            target: target.parse().unwrap(),
            mapping: StunMapping {
                ip: "1.2.3.4".to_string(),
                port: mapped_port,
            },
            alt_server: None,
        }
    }

    #[test]
    fn identical_ports_across_ips_classify_as_cone() {
        let s = vec![
            sample("9.9.9.9:3478", 50000),
            sample("9.9.9.9:3479", 50000),
            sample("8.8.8.8:3478", 50000),
        ];
        let (class, step, conf, adm) = classify(&s);
        assert_eq!(class, NatClass::Cone);
        assert_eq!(step, 0);
        assert!(conf >= 1.0);
        assert!(!adm);
    }

    #[test]
    fn incrementing_ports_classify_as_linear() {
        let s = vec![
            sample("9.9.9.9:3478", 50000),
            sample("9.9.9.9:3479", 50001),
            sample("9.9.9.9:3480", 50002),
            sample("9.9.9.9:3481", 50003),
        ];
        let (class, step, conf, adm) = classify(&s);
        assert_eq!(class, NatClass::LinearSymmetric);
        assert_eq!(step, 1);
        assert!(conf > 0.9);
        assert!(!adm);
    }

    #[test]
    fn jumpy_ports_classify_as_random() {
        let s = vec![
            sample("9.9.9.9:3478", 50000),
            sample("9.9.9.9:3479", 9312),
            sample("9.9.9.9:3480", 41200),
            sample("9.9.9.9:3481", 1099),
        ];
        let (class, step, _, _) = classify(&s);
        assert_eq!(class, NatClass::RandomSymmetric);
        assert_eq!(step, 0);
    }

    #[test]
    fn adm_symmetric_is_detected_across_ips() {
        // 每个目标 IP 内部映射稳定、跨 IP 端口前进——单 IP 采样会把它当锥形，
        // 这正是 "日志 cone_to_cone 却打不通" 的元凶之一
        let s = vec![
            sample("9.9.9.9:3478", 50000),
            sample("9.9.9.9:3479", 50000),
            sample("8.8.8.8:3478", 50002),
        ];
        let (class, step, _, adm) = classify(&s);
        assert_eq!(class, NatClass::LinearSymmetric);
        assert_eq!(step, 2);
        assert!(adm);
        assert_eq!(detail_name(class, step, adm), "symmetric_adm_step2");
    }

    #[test]
    fn adm_with_unpredictable_ports_is_random_symmetric() {
        let s = vec![
            sample("9.9.9.9:3478", 50000),
            sample("9.9.9.9:3479", 50000),
            sample("8.8.8.8:3478", 3777),
        ];
        let (class, _, _, adm) = classify(&s);
        assert_eq!(class, NatClass::RandomSymmetric);
        assert!(adm);
    }

    #[test]
    fn single_ip_sampling_cannot_see_adm_and_stays_cone() {
        // 结构性盲区：只有一个目标 IP 时 ADM 与锥形不可区分，
        // classify 只能给 Cone——probe() 里对应的 WARN 必须存在
        let s = vec![sample("9.9.9.9:3478", 50000), sample("9.9.9.9:3479", 50000)];
        let (class, _, _, adm) = classify(&s);
        assert_eq!(class, NatClass::Cone);
        assert!(!adm);
    }

    #[test]
    fn single_sample_is_optimistically_cone() {
        // 只有一个采样点无法判定映射行为；按锥形试一次的成本远低于直接放弃
        let (class, _, conf, _) = classify(&[sample("9.9.9.9:3478", 50000)]);
        assert_eq!(class, NatClass::Cone);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn no_sample_is_unknown() {
        let (class, _, _, _) = classify(&[]);
        assert_eq!(class, NatClass::Unknown);
    }

    #[test]
    fn step_uses_mode_not_mean() {
        // 大多数步进为 2，个别为 9；众数应给出 2 而不是被拉高的平均值
        let s = vec![
            sample("9.9.9.9:3478", 1000),
            sample("9.9.9.9:3479", 1002),
            sample("9.9.9.9:3480", 1004),
            sample("9.9.9.9:3481", 1013),
            sample("9.9.9.9:3482", 1015),
        ];
        let (class, step, _, _) = classify(&s);
        assert_eq!(class, NatClass::LinearSymmetric);
        assert_eq!(step, 2);
    }

    fn profile_with(base_port: u16, step: i32, ip: &str) -> NatProfile {
        NatProfile {
            eph_public: [0u8; 32],
            eph_signature: [0u8; 64],
            identity_public: [0u8; 32],
            class: NatClass::LinearSymmetric,
            detail: "t".into(),
            base_port,
            step,
            step_confidence: 1.0,
            sample_ports: vec![],
            public_ip: Some(ip.to_string()),
            has_ipv6: false,
            ipv6_addrs: vec![],
            network_type: NetworkType::Unknown,
            signal_rtt_ms: 10,
        }
    }

    #[test]
    fn linear_predict_walks_forward_by_step() {
        let params = PunchParams::for_strategy(PunchStrategy::ConeToLinear);
        let peer = profile_with(40000, 2, "5.6.7.8");
        let t = build_targets(params, &peer, &[]);
        // 应包含 base + step*k
        assert!(t.contains(&"5.6.7.8:40002".parse().unwrap()));
        assert!(t.contains(&"5.6.7.8:40004".parse().unwrap()));
        assert_eq!(t.len(), params.target_port_count as usize);
    }

    #[test]
    fn fixed_mode_only_uses_reported_candidates() {
        // RandomToCone：对端是锥形，端口固定且已知，不该再撒网
        let params = PunchParams::for_strategy(PunchStrategy::RandomToCone);
        assert_eq!(params.target_port_mode, TargetPortMode::Fixed);
        let peer = profile_with(40000, 0, "5.6.7.8");
        let cand = IceCandidate {
            ip: "5.6.7.8".into(),
            port: 40000,
            ctype: CandidateType::ServerReflexive,
            priority: 1,
            foundation: "s0".into(),
        };
        let t = build_targets(params, &peer, &[cand]);
        assert_eq!(t.len(), 1, "固定模式下不应生成额外目标");
    }

    #[test]
    fn random_spray_produces_requested_width() {
        let params = PunchParams::for_strategy(PunchStrategy::ConeToRandom);
        let peer = profile_with(40000, 0, "5.6.7.8");
        let t = build_targets(params, &peer, &[]);
        assert!(t.len() >= params.target_port_count as usize);
    }

    #[test]
    fn peer_candidates_are_always_targeted() {
        let params = PunchParams::for_strategy(PunchStrategy::ConeToCone);
        let peer = profile_with(40000, 0, "5.6.7.8");
        let cands: Vec<IceCandidate> = ["9.9.9.9", "8.8.8.8"]
            .iter()
            .enumerate()
            .map(|(i, ip)| IceCandidate {
                ip: (*ip).into(),
                port: 1000 + i as u16,
                ctype: CandidateType::ServerReflexive,
                priority: 1,
                foundation: format!("s{i}"),
            })
            .collect();
        let t = build_targets(params, &peer, &cands);
        assert!(t.contains(&"9.9.9.9:1000".parse().unwrap()));
        assert!(t.contains(&"8.8.8.8:1001".parse().unwrap()));
    }

    #[test]
    fn ack_packets_are_distinguishable_and_echo_timestamp() {
        let probe = make_packet();
        assert!(!is_ack(&probe));
        let sent_at = u64::from_be_bytes(probe[4..12].try_into().unwrap());
        let ack = make_ack(sent_at);
        assert!(is_ack(&ack));
        // 应答必须回显对端的时间戳，否则算不出真实 RTT
        assert_eq!(&ack[4..12], &probe[4..12]);
    }

    /// 双栈 socket 必须把 IPv4 目标转成 IPv4-mapped 才能发出去。
    ///
    /// 回归测试：曾经漏掉这一步，导致 `send_to` 对每个 IPv4 目标都返回
    /// `WSAEFAULT(10014)`，纯 IPv4 环境 100% 打洞失败并静默退化到中继；
    /// 而 IPv6 目标不需要转换，所以有 IPv6 的环境把问题完全掩盖了。
    #[test]
    fn ipv4_targets_are_mapped_for_dual_stack_sockets() {
        let sock = network::bind_dual_stack_udp(0).expect("bind dual-stack");
        assert!(
            sock.local_addr().unwrap().is_ipv6(),
            "打洞 socket 应为 AF_INET6 双栈"
        );

        let v4: SocketAddr = "192.168.1.100:59854".parse().unwrap();
        let mapped = network::compatible_socket_addr(&sock, v4);
        assert!(
            mapped.is_ipv6(),
            "IPv4 目标必须转成 IPv4-mapped，否则 send_to 会 WSAEFAULT"
        );
        assert_eq!(mapped.port(), 59854, "端口不能在转换中丢失");
        match mapped.ip() {
            IpAddr::V6(v6) => assert_eq!(
                v6.to_ipv4_mapped(),
                Some("192.168.1.100".parse().unwrap()),
                "映射后应能还原出原始 IPv4"
            ),
            _ => panic!("期望 IPv6 形式"),
        }

        // IPv6 目标必须原样保留
        let v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        assert_eq!(network::compatible_socket_addr(&sock, v6), v6);
    }

    #[test]
    fn permanent_failures_are_recognised() {
        use std::io::Error;
        assert!(is_permanent_failure(&Error::from(
            ErrorKind::NetworkUnreachable
        )));
        assert!(is_permanent_failure(&Error::from(
            ErrorKind::HostUnreachable
        )));
        assert!(is_permanent_failure(&Error::from(
            ErrorKind::AddrNotAvailable
        )));
        // WouldBlock 是正常的非阻塞返回，绝不能当成永久失败摘除目标
        assert!(!is_permanent_failure(&Error::from(ErrorKind::WouldBlock)));
    }
}
