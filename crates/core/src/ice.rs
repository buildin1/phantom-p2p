//! ICE 候选收集与多策略打洞引擎
//!
//! 实现参考 UU远程 逆向分析结果，支持 7 种打洞策略：
//!
//! 1. **多 STUN 服务器候选**：从多个 STUN 服务器收集 srflx 候选
//! 2. **同局域网直连**：公网 IP 相同时尝试内网 IP 直连
//! 3. **IPv6 直连**：双方都有 IPv6 时优先 IPv6
//! 4. **端口递增预测**：对 SymmetricIncremental NAT 预测下一个端口
//! 5. **端口范围扫射**：对 SymmetricRandom NAT 扫射 ±N 端口范围
//! 6. **双向对称打洞**：双方同时扫射对方的端口范围
//! 7. **多公网路径**：CGNAT / 多 ISP 场景下枚举所有映射候选
//!
//! 核心设计：
//! - 复用 STUN 探测阶段绑定的同一个 UDP socket（确保 NAT 映射一致）
//! - 同时向所有候选地址发送 PUNCH_MAGIC 包，最先响应的候选胜出
//! - 与现有 QUIC 隧道层完全兼容（打洞成功的 socket 直接传给 quinn）

use crate::network;
use crate::stun;
use phantom_protocol::{CandidateType, IceCandidate};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// 打洞包魔数（与 puncher.rs 保持一致）
const PUNCH_MAGIC: &[u8; 4] = b"PP6P";

/// 每个候选的发包间隔（毫秒）
/// 10ms 更积极，对端口限制锥形 NAT 打洞窗口更友好
const ICE_SEND_INTERVAL_MS: u64 = 10;

/// 整体打洞超时（秒）——与 UU远程相同的 12秒倒计时
const ICE_TIMEOUT_SECS: u64 = 12;

// ============================================================
// ICE 优先级计算（RFC 8445 §5.1.2.1）
// ============================================================

/// 计算 ICE 候选优先级
/// priority = 2^24 * type_preference + 2^8 * local_preference + (2^0 * (256 - component_id))
pub fn ice_priority(ctype: CandidateType, local_preference: u16) -> u32 {
    let type_pref: u32 = match ctype {
        CandidateType::Host => 126,
        CandidateType::ServerReflexive => 100,
        // 策略候选是预测/撒网出来的猜测地址，绝大多数不会命中，
        // 优先级必须低于真实探测到的 srflx，但高于中继。
        CandidateType::Strategy => 50,
        CandidateType::Relay => 0,
    };
    (1u32 << 24) * type_pref + (1u32 << 8) * (local_preference as u32) + 255
}

/// IPv6 Host 候选专用优先级
/// IPv6 通常不经过 NAT，直连成功率接近 100%，应高于 IPv4 Host
/// type_pref=127（高于 IPv4 Host 的 126），local_pref=255
pub fn ice_priority_ipv6_host() -> u32 {
    (1u32 << 24) * 127 + (1u32 << 8) * 255 + 255
}

// ============================================================
// 策略 1+7: 主机候选收集（本地 IP 地址）
// ============================================================

/// 获取所有本机 IPv4 地址（排除回环、链路本地、以及本产品自己的 overlay 网段）
fn get_all_local_ipv4s() -> Vec<String> {
    let mut result = Vec::new();

    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in interfaces {
            if let IpAddr::V4(v4) = ip {
                // 名字过滤在 macOS 上不生效（utun 设备名由内核分配，不是
                // 我们请求的 phantomp2p*）；退化到"网卡名是 utunN 且地址
                // 落在 overlay 网段"兜底排除，见 network::is_overlay_adapter
                // 同款逻辑的说明——不能只按网段过滤，会误伤用户自己就用
                // 172.16/12 的真实局域网。
                if is_overlay_interface(&name)
                    || (network::is_macos_utun_name(&name) && network::is_overlay_subnet_ipv4(&v4))
                {
                    continue;
                }
            } else if is_overlay_interface(&name) {
                continue;
            }
            if ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified() {
                let value = ip.to_string();
                if !result.contains(&value) {
                    result.push(value);
                }
            }
        }
    }

    // 尝试通过连接外网地址的方式探测所有本地 IP（多网卡）
    for target in &["1.1.1.1:80", "8.8.8.8:80", "223.5.5.5:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let ip_str = local.ip().to_string();
                    if !result.contains(&ip_str) && !local.ip().is_loopback() {
                        result.push(ip_str);
                    }
                }
            }
        }
    }

    result
}

fn get_all_global_ipv6s() -> Vec<String> {
    let mut result = Vec::new();
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in interfaces {
            if is_overlay_interface(&name) {
                continue;
            }
            let IpAddr::V6(ip) = ip else {
                continue;
            };
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
            {
                continue;
            }
            let value = ip.to_string();
            if !result.contains(&value) {
                result.push(value);
            }
        }
    }
    result
}

fn is_overlay_interface(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("phantomp2p")
}

/// 策略 1+2+7: 收集主机候选（Host Candidates）
pub fn gather_host_candidates(sock: &UdpSocket) -> Vec<IceCandidate> {
    let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut result = Vec::new();
    let local_ips = get_all_local_ipv4s();

    for (idx, ip) in local_ips.iter().enumerate() {
        let pref = (255u16).saturating_sub(idx as u16);
        result.push(IceCandidate {
            ip: ip.clone(),
            port: local_port,
            ctype: CandidateType::Host,
            priority: ice_priority(CandidateType::Host, pref),
            foundation: format!("h{}", idx),
        });
    }

    // 策略 3: IPv6 主机候选（优先级最高：IPv6 直连无 NAT）
    for (idx, ipv6_addr) in get_all_global_ipv6s().into_iter().enumerate() {
        result.push(IceCandidate {
            ip: ipv6_addr,
            port: local_port,
            ctype: CandidateType::Host,
            priority: ice_priority_ipv6_host().saturating_sub(idx as u32),
            foundation: format!("h_ipv6_{}", idx),
        });
    }

    result
}

// ============================================================
// 策略 1+5: 服务器反射候选（STUN 多服务器）
// ============================================================

/// 收集服务器反射候选（Server Reflexive Candidates）
pub fn gather_srflx_candidates(sock: &UdpSocket) -> Vec<IceCandidate> {
    let mappings = stun::query_all(sock);
    let mut seen_endpoints: HashSet<(String, u16)> = HashSet::new();
    let mut result = Vec::new();

    for (idx, mapping) in mappings.iter().enumerate() {
        let key = (mapping.ip.clone(), mapping.port);
        if seen_endpoints.contains(&key) {
            continue;
        }
        seen_endpoints.insert(key);

        let pref = (255u16).saturating_sub(idx as u16);
        result.push(IceCandidate {
            ip: mapping.ip.clone(),
            port: mapping.port,
            ctype: CandidateType::ServerReflexive,
            priority: ice_priority(CandidateType::ServerReflexive, pref),
            foundation: format!("s{}", idx),
        });
    }

    result
}

// ============================================================
// 策略 4+5+6: 对称 NAT 端口预测
// ============================================================

/// 分析端口映射规律，返回步长（0 = 无规律/随机）
fn analyze_port_pattern(mappings: &[stun::StunMapping]) -> i32 {
    if mappings.len() < 2 {
        return 0;
    }
    let ports: Vec<i32> = mappings.iter().map(|m| m.port as i32).collect();
    let diffs: Vec<i32> = ports.windows(2).map(|w| w[1] - w[0]).collect();
    let positive_small: Vec<i32> = diffs
        .iter()
        .filter(|&&d| d > 0 && d <= 16)
        .cloned()
        .collect();

    if positive_small.len() * 2 >= diffs.len() && !positive_small.is_empty() {
        // 递增模式：返回平均步长
        let avg = positive_small.iter().sum::<i32>() / positive_small.len() as i32;
        avg.max(1).min(8)
    } else {
        0 // 随机/无规律
    }
}

/// 策略 4+5+6: 为对称 NAT 生成端口预测候选
/// base_ip: 基准公网 IP
/// base_port: 最后一次 STUN 探测到的端口（最新映射）
/// mappings: 所有 STUN 映射（用于分析递增步长）
/// count: 预测候选数量
pub fn generate_symmetric_candidates(
    base_ip: &str,
    base_port: u16,
    mappings: &[stun::StunMapping],
    count: usize,
) -> Vec<IceCandidate> {
    let step = analyze_port_pattern(mappings);
    let mut result = Vec::new();

    if step > 0 {
        // 策略 4: 递增预测（向前预测 count 个）
        for i in 1..=(count as i32) {
            let predicted = base_port as i32 + step * i;
            if predicted > 0 && predicted <= 65535 {
                result.push(IceCandidate {
                    ip: base_ip.to_string(),
                    port: predicted as u16,
                    ctype: CandidateType::ServerReflexive,
                    priority: ice_priority(
                        CandidateType::ServerReflexive,
                        (150u16).saturating_sub(i as u16 * 2),
                    ),
                    foundation: format!("pred_inc_{}", i),
                });
            }
        }
    } else {
        // 策略 5+6: 随机对称，扫射 ±count 端口范围
        for i in 1..=(count as u16) {
            if let Some(p) = base_port.checked_add(i) {
                result.push(IceCandidate {
                    ip: base_ip.to_string(),
                    port: p,
                    ctype: CandidateType::ServerReflexive,
                    priority: ice_priority(
                        CandidateType::ServerReflexive,
                        (120u16).saturating_sub(i),
                    ),
                    foundation: format!("sweep_p{}", i),
                });
            }
            if let Some(p) = base_port.checked_sub(i) {
                result.push(IceCandidate {
                    ip: base_ip.to_string(),
                    port: p,
                    ctype: CandidateType::ServerReflexive,
                    priority: ice_priority(
                        CandidateType::ServerReflexive,
                        (120u16).saturating_sub(i),
                    ),
                    foundation: format!("sweep_m{}", i),
                });
            }
        }
    }

    result
}

// ============================================================
// 完整候选收集（供 puncher.rs 调用）
// ============================================================

/// 收集本端所有 ICE 候选地址（7 种策略的候选集合）
///
/// 返回: (candidates, ufrag, pwd, nat_type_key)
/// - nat_type_key 供服务端决策（是否需要端口预测）
pub fn gather_all_candidates(sock: &UdpSocket) -> (Vec<IceCandidate>, String, String, String) {
    let mut candidates = Vec::new();

    // 策略 1+2+3+7: 主机候选
    candidates.extend(gather_host_candidates(sock));

    // 策略 1+5: srflx 候选（多 STUN 服务器）
    let srflx = gather_srflx_candidates(sock);

    // 策略 4+5+6: 对称 NAT 预测候选（只在有多个 srflx 且端口不同时触发）
    let mappings = stun::query_all(sock);
    let has_symmetric = {
        let ports: Vec<u16> = mappings.iter().map(|m| m.port).collect();
        ports.len() >= 2 && !ports.iter().all(|&p| p == ports[0])
    };

    if has_symmetric {
        // 对称 NAT：添加端口预测候选
        if let Some(last_mapping) = mappings.last() {
            let predicted = generate_symmetric_candidates(
                &last_mapping.ip,
                last_mapping.port,
                &mappings,
                50, // enable_ice_full_punch: 扫射 50 个端口（UU远程激进策略）
            );
            candidates.extend(predicted);
        }
    }

    candidates.extend(srflx);

    // 去重 + 按优先级排序
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    candidates.retain(|c| seen.insert((c.ip.clone(), c.port)));
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

    // 生成 ICE 凭证
    let ufrag = generate_ice_ufrag();
    let pwd = generate_ice_pwd();

    // 分析 NAT 类型
    let nat_type_key = if has_symmetric {
        let step = analyze_port_pattern(&mappings);
        if step > 0 {
            "symmetric_incremental".to_string()
        } else {
            "symmetric_random".to_string()
        }
    } else if mappings.is_empty() {
        "unknown".to_string()
    } else {
        "port_restricted_cone".to_string() // 保守估计
    };

    info!(
        "[ICE] 候选收集完成: {} 个候选, NAT={}, ufrag={}",
        candidates.len(),
        nat_type_key,
        ufrag
    );

    (candidates, ufrag, pwd, nat_type_key)
}

// ============================================================
// ICE 凭证生成
// ============================================================

fn generate_ice_ufrag() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let c: u8 = rng.gen_range(0..36);
            if c < 10 {
                (b'0' + c) as char
            } else {
                (b'a' + c - 10) as char
            }
        })
        .collect()
}

fn generate_ice_pwd() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| {
            let c: u8 = rng.gen_range(0..62);
            match c {
                0..=9 => (b'0' + c) as char,
                10..=35 => (b'a' + c - 10) as char,
                _ => (b'A' + c - 36) as char,
            }
        })
        .collect()
}

// ============================================================
// ICE 连通性检测（核心打洞逻辑）
// ============================================================

/// ICE 连通性检测结果
#[derive(Debug, Clone)]
pub struct IceCheckResult {
    /// 成功连通的对端地址
    pub peer_addr: SocketAddr,
    /// RTT 毫秒
    pub rtt_ms: u32,
    /// 使用的候选类型
    pub ctype: CandidateType,
}

/// 执行 ICE 连通性检测
///
/// 实现了 RFC 8445 的核心行为，参考 UU远程 libstreamer.dylib 分析结果：
///
/// 1. **同步开始**：等待 start_at_ms 时间戳，双方精确同步启动
/// 2. **全量发包**（enable_ice_full_punch）：向所有已知候选地址同时发包
/// 3. **Triggered Check**：收到来自未知地址的包（Peer Reflexive Candidate）时，
///    立刻将该地址加入发包目标列表，同时回发确认——这是端口限制锥形 NAT 的关键
/// 4. **双向确认**：收到首个响应后，继续发包 200ms 确保对端也收到我方确认，
///    防止单边打洞误判
/// 5. **12秒倒计时**：与 UU远程相同的超时策略
///
/// 参数：
/// - sock: 打洞用的 UDP socket（已设置为非阻塞）
/// - peer_candidates: 对端的 ICE 候选地址列表
/// - start_at_ms: Unix 毫秒时间戳，双方同步开始时间
///
/// 返回: Some(IceCheckResult) 表示连通，None 表示超时
pub async fn run_connectivity_checks(
    sock: Arc<UdpSocket>,
    peer_candidates: &[IceCandidate],
    start_at_ms: u64,
) -> Option<IceCheckResult> {
    if peer_candidates.is_empty() {
        warn!("[ICE] 无对端候选，放弃连通性检测");
        return None;
    }

    // 解析对端候选地址 → 用 Mutex 保护的动态列表（triggered check 会向其追加 prflx）
    let initial_addrs: Vec<(SocketAddr, CandidateType)> = peer_candidates
        .iter()
        .filter_map(|c| {
            c.ip.parse::<IpAddr>().ok().map(|ip| {
                let addr = SocketAddr::new(ip, c.port);
                (network::compatible_socket_addr(&sock, addr), c.ctype)
            })
        })
        .collect();

    if initial_addrs.is_empty() {
        warn!("[ICE] 所有对端候选地址解析失败");
        return None;
    }

    // 构建已知地址集合（用于 prflx 去重）
    let mut known_addrs: HashSet<SocketAddr> = initial_addrs.iter().map(|(a, _)| *a).collect();
    // 动态候选列表（prflx triggered check 会追加）
    let mut send_list: Vec<(SocketAddr, CandidateType)> = initial_addrs;

    info!(
        "[ICE] 开始连通性检测: {} 个对端候选 (超时 {}s)",
        send_list.len(),
        ICE_TIMEOUT_SECS,
    );

    // 设置非阻塞
    if let Err(e) = sock.set_nonblocking(true) {
        warn!("[ICE] 设置非阻塞失败: {}", e);
    }

    // 等待同步时间（精确到毫秒，与对端对齐）
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if start_at_ms > now_ms {
        let wait = start_at_ms - now_ms;
        if wait <= 2000 {
            info!("[ICE] 等待 {}ms 同步开始", wait);
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(ICE_TIMEOUT_SECS);
    let mut last_send = Instant::now() - Duration::from_millis(ICE_SEND_INTERVAL_MS);
    let mut send_seq: u32 = 0;
    let mut buf = [0u8; 256];

    // 首次收到响应的地址（triggered check 后的双向确认窗口起点）
    let mut first_success: Option<(SocketAddr, CandidateType, u32)> = None;
    // 双向确认窗口：收到首个响应后，继续发包 200ms 确保对端也能收到回包
    let confirm_window = Duration::from_millis(200);

    loop {
        let now = Instant::now();
        if now >= deadline {
            warn!("[ICE] 连通性检测超时 ({}s)", ICE_TIMEOUT_SECS);
            return None;
        }

        // 双向确认窗口结束 → 正式返回成功
        if let Some((addr, ctype, rtt)) = first_success {
            if now.duration_since(start) >= confirm_window + Duration::from_millis(rtt as u64) {
                info!(
                    "[ICE] ✅ 双向确认完成，最终候选: {} ({:?}), RTT ~{}ms, send_list={}个",
                    addr,
                    ctype,
                    rtt,
                    send_list.len()
                );
                return Some(IceCheckResult {
                    peer_addr: addr,
                    rtt_ms: rtt,
                    ctype,
                });
            }
        }

        // 每 ICE_SEND_INTERVAL_MS 发一轮（向全部候选，包括动态追加的 prflx）
        if now.duration_since(last_send) >= Duration::from_millis(ICE_SEND_INTERVAL_MS) {
            let elapsed_ms = now.duration_since(start).as_millis() as u32;
            let mut packet = Vec::with_capacity(8);
            packet.extend_from_slice(PUNCH_MAGIC);
            packet.extend_from_slice(&elapsed_ms.to_be_bytes());

            for (addr, _) in &send_list {
                match sock.send_to(&packet, addr) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        debug!("[ICE] 发包到 {} 失败: {}", addr, e);
                    }
                }
            }

            send_seq += 1;
            if send_seq % 100 == 0 {
                debug!(
                    "[ICE] 已发 {} 轮, 候选 {} 个 (含prflx), 已用 {}ms",
                    send_seq,
                    send_list.len(),
                    now.duration_since(start).as_millis()
                );
            }

            last_send = now;
        }

        // 接收
        match sock.recv_from(&mut buf) {
            Ok((len, from_addr)) => {
                if len >= 8 && &buf[..4] == PUNCH_MAGIC {
                    let elapsed = start.elapsed().as_millis() as u32;

                    // 查找来源是否是已知候选
                    let ctype = send_list
                        .iter()
                        .find(|(a, _)| *a == from_addr)
                        .map(|(_, t)| *t)
                        .unwrap_or(CandidateType::ServerReflexive);

                    // ── Triggered Check ──────────────────────────────────────
                    // 若来自未知地址（Peer Reflexive Candidate），立刻加入发包列表
                    // 这是对称 NAT 场景下最关键的机制：
                    //   对端的实际 NAT 出口端口与我们预测的不同，
                    //   但它的包穿过了我们的锥形 NAT，我们必须立刻回发，
                    //   才能打开对端防火墙的入方向。
                    if !known_addrs.contains(&from_addr) {
                        known_addrs.insert(from_addr);
                        send_list.push((from_addr, CandidateType::ServerReflexive));
                        info!(
                            "[ICE] 🔀 Triggered Check: 发现 Peer Reflexive 候选 {}，已加入发包列表",
                            from_addr
                        );
                    }

                    // 立刻回发确认包（打开对端的 NAT 入方向）
                    let mut ack = Vec::with_capacity(8);
                    ack.extend_from_slice(PUNCH_MAGIC);
                    ack.extend_from_slice(&elapsed.to_be_bytes());
                    let _ = sock.send_to(&ack, from_addr);

                    // 记录首次成功，进入双向确认窗口（继续发包 200ms）
                    if first_success.is_none() {
                        info!(
                            "[ICE] 📶 首次收到响应: {} ({:?}), RTT ~{}ms, 进入双向确认窗口...",
                            from_addr,
                            ctype,
                            elapsed.min(500)
                        );
                        first_success = Some((from_addr, ctype, elapsed.min(500)));
                    }
                } else {
                    // 非 PUNCH 包（可能是 QUIC/其他数据），忽略
                    debug!("[ICE] 收到非 PUNCH 包 {} 字节 from {}", len, from_addr);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                debug!("[ICE] 接收错误: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ============================================================
// 防火墙预检（借鉴 UU远程 PunchCheckFireWall）
// ============================================================

/// 快速检测本地防火墙是否拦截 UDP（发出并回环测试）
/// 返回: true = 可以正常发送 UDP
pub async fn check_udp_reachable() -> bool {
    // 绑定两个临时 socket，互相发包
    let sock_a = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return true, // 绑定失败时乐观返回
    };
    let sock_b = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return true,
    };

    let port_b = match sock_b.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return true,
    };

    let _ = sock_a.set_nonblocking(true);
    let _ = sock_b.set_nonblocking(true);

    let test_data = b"PPFW";
    let _ = sock_a.send_to(test_data, format!("127.0.0.1:{}", port_b));

    // 等待最多 100ms
    let start = Instant::now();
    let mut buf = [0u8; 16];
    while start.elapsed() < Duration::from_millis(100) {
        match sock_b.recv_from(&mut buf) {
            Ok((4, _)) if &buf[..4] == b"PPFW" => return true,
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    warn!("[ICE] 本地 UDP 回环测试失败，可能存在防火墙");
    false
}

#[cfg(test)]
mod tests {
    use super::is_overlay_interface;

    #[test]
    fn phantom_interfaces_are_excluded_from_ice() {
        assert!(is_overlay_interface("PhantomP2P"));
        assert!(is_overlay_interface("PhantomP2P-172-16-1-2"));
        assert!(is_overlay_interface("phantomp2p-test"));
        assert!(!is_overlay_interface("Ethernet"));
    }
}
