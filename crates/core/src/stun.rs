//! STUN 客户端实现（RFC 5389 / RFC 8489 / RFC 5780 部分能力）
//!
//! 使用 UDP Binding Request 查询公网映射 (XOR-MAPPED-ADDRESS / MAPPED-ADDRESS)。
//! 与 Python 的 `stun.py` 保持接口一致。

use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// 单次 STUN 查询结果
///
/// 包含查询到的公网 IP 和端口。
/// 与 Python 的 `{'ip': ..., 'port': ...}` 对齐。
#[derive(Debug, Clone)]
pub struct StunMapping {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct StunServerSample {
    pub server: String,
    pub mapping: StunMapping,
    pub rtt_ms: u32,
}

#[derive(Debug, Clone)]
pub struct StunQueryResult {
    pub mapping: StunMapping,
    pub rtt_ms: u32,
    pub responder_addr: SocketAddr,
    pub response_origin: Option<SocketAddr>,
    pub other_address: Option<SocketAddr>,
    pub changed_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteringBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressPortDependent,
    Unknown,
}

impl FilteringBehavior {
    pub fn key(&self) -> &'static str {
        match self {
            FilteringBehavior::EndpointIndependent => "endpoint_independent",
            FilteringBehavior::AddressDependent => "address_dependent",
            FilteringBehavior::AddressPortDependent => "address_port_dependent",
            FilteringBehavior::Unknown => "unknown",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            FilteringBehavior::EndpointIndependent => "Endpoint Independent Filtering",
            FilteringBehavior::AddressDependent => "Address Dependent Filtering",
            FilteringBehavior::AddressPortDependent => "Address+Port Dependent Filtering",
            FilteringBehavior::Unknown => "Filtering 未知",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilteringProbeResult {
    pub behavior: FilteringBehavior,
    pub detail: String,
    pub server: String,
}

/// STUN 服务器列表（与 Python 版一致）
pub const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.dcalling.de", 3478),
    ("stun.skydrone.aero", 3478),
    ("stun.nextcloud.com", 443),
];

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// 使用已有的 UDP socket 查询一个 STUN 服务器，返回公网映射地址。
/// 与 Python 的 `STUNClient.query(sock, stun_server)` 完全对齐。
pub fn query(sock: &UdpSocket, stun_addr: SocketAddr) -> Option<StunMapping> {
    query_with_options(sock, stun_addr, false, false).map(|r| r.mapping)
}

/// 解析 XOR-MAPPED-ADDRESS 属性（RFC 5389 §15.2）
fn parse_xor_mapped_address(attr: &[u8], _transaction_id: &[u8; 12]) -> Option<StunMapping> {
    if attr.len() < 8 {
        return None;
    }
    let family = attr[1];
    if family != 0x01 {
        // 只处理 IPv4
        return None;
    }

    let x_port = u16::from_be_bytes([attr[2], attr[3]]);
    let port = x_port ^ (MAGIC_COOKIE >> 16) as u16;

    let x_ip = u32::from_be_bytes([attr[4], attr[5], attr[6], attr[7]]);
    let ip_int = x_ip ^ MAGIC_COOKIE;
    let ip = format!(
        "{}.{}.{}.{}",
        (ip_int >> 24) & 0xFF,
        (ip_int >> 16) & 0xFF,
        (ip_int >> 8) & 0xFF,
        ip_int & 0xFF
    );

    Some(StunMapping { ip, port })
}

/// 解析 MAPPED-ADDRESS 属性（RFC 5389 §15.1）—— fallback
fn parse_mapped_address(attr: &[u8]) -> Option<StunMapping> {
    if attr.len() < 8 {
        return None;
    }
    let family = attr[1];
    if family != 0x01 {
        return None;
    }

    let port = u16::from_be_bytes([attr[2], attr[3]]);
    let ip = format!("{}.{}.{}.{}", attr[4], attr[5], attr[6], attr[7]);

    Some(StunMapping { ip, port })
}

fn build_binding_request(change_ip: bool, change_port: bool) -> ([u8; 12], Vec<u8>) {
    let mut rng = rand::thread_rng();
    let transaction_id: [u8; 12] = rng.gen();

    let mut attrs = Vec::new();
    if change_ip || change_port {
        let mut flag = 0u32;
        if change_ip {
            flag |= 0x04;
        }
        if change_port {
            flag |= 0x02;
        }
        attrs.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.extend_from_slice(&flag.to_be_bytes());
    }

    let mut msg = Vec::with_capacity(20 + attrs.len());
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&transaction_id);
    msg.extend_from_slice(&attrs);
    (transaction_id, msg)
}

fn parse_addr_attribute(attr_type: u16, attr_data: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    let mapped = if attr_type == ATTR_XOR_MAPPED_ADDRESS {
        parse_xor_mapped_address(attr_data, txid)
    } else {
        parse_mapped_address(attr_data)
    }?;
    format!("{}:{}", mapped.ip, mapped.port).parse().ok()
}

pub fn query_with_options(
    sock: &UdpSocket,
    stun_addr: SocketAddr,
    change_ip: bool,
    change_port: bool,
) -> Option<StunQueryResult> {
    debug!(
        "[STUN] 发送 Binding Request → {} (change_ip={}, change_port={})",
        stun_addr, change_ip, change_port
    );

    let (transaction_id, msg) = build_binding_request(change_ip, change_port);
    sock.set_read_timeout(Some(STUN_TIMEOUT)).ok()?;
    let start = Instant::now();
    let stun_addr = crate::network::compatible_socket_addr(sock, stun_addr);
    if let Err(e) = sock.send_to(&msg, stun_addr) {
        warn!("[STUN] 发送到 {} 失败: {}", stun_addr, e);
        return None;
    }

    let mut buf = [0u8; 1500];
    loop {
        let (n, responder_addr) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                warn!("[STUN] 接收 {} 超时或失败: {}", stun_addr, e);
                return None;
            }
        };
        let data = &buf[..n];
        if data.len() < 20 {
            continue;
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != BINDING_RESPONSE {
            continue;
        }

        if data[4..8] != MAGIC_COOKIE.to_be_bytes() {
            continue;
        }
        if data[8..20] != transaction_id {
            if start.elapsed() >= STUN_TIMEOUT {
                return None;
            }
            continue;
        }

        let msg_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut pos = 20usize;
        let mut xor_result: Option<StunMapping> = None;
        let mut mapped_result: Option<StunMapping> = None;
        let mut other_address: Option<SocketAddr> = None;
        let mut changed_address: Option<SocketAddr> = None;
        let mut response_origin: Option<SocketAddr> = None;

        while pos + 4 <= data.len() && pos < 20 + msg_length {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            if pos + 4 + attr_len > data.len() {
                break;
            }
            let attr_data = &data[pos + 4..pos + 4 + attr_len];
            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    if let Some(m) = parse_xor_mapped_address(attr_data, &transaction_id) {
                        xor_result = Some(m);
                    }
                }
                ATTR_MAPPED_ADDRESS => {
                    if let Some(m) = parse_mapped_address(attr_data) {
                        mapped_result = Some(m);
                    }
                }
                ATTR_OTHER_ADDRESS => {
                    other_address = parse_addr_attribute(attr_type, attr_data, &transaction_id);
                }
                ATTR_CHANGED_ADDRESS => {
                    changed_address = parse_addr_attribute(attr_type, attr_data, &transaction_id);
                }
                ATTR_RESPONSE_ORIGIN => {
                    response_origin = parse_addr_attribute(attr_type, attr_data, &transaction_id);
                }
                _ => {}
            }

            let padded = (attr_len + 3) & !3;
            pos += 4 + padded;
        }

        let mapping = xor_result.or(mapped_result)?;
        let rtt_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        return Some(StunQueryResult {
            mapping,
            rtt_ms,
            responder_addr,
            response_origin,
            other_address,
            changed_address,
        });
    }
}

/// 使用同一个 UDP socket 依次查询所有 STUN 服务器，收集映射结果。
/// 与 Python 中 `for stun_server in STUN_SERVERS: result = STUNClient.query(sock, stun_server)` 对齐。
pub fn query_all(sock: &UdpSocket) -> Vec<StunMapping> {
    query_all_detailed(sock)
        .into_iter()
        .map(|s| s.mapping)
        .collect()
}

fn resolve_stun_addr(host: &str, port: u16) -> Option<SocketAddr> {
    match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => addrs.find(|a| a.is_ipv4()),
        Err(_) => None,
    }
}

pub fn query_all_detailed(sock: &UdpSocket) -> Vec<StunServerSample> {
    let mut samples = Vec::new();
    info!(
        "[STUN] 开始查询 {} 个 STUN 服务器 (socket 本地地址: {:?})",
        STUN_SERVERS.len(),
        sock.local_addr()
    );

    for &(host, port) in STUN_SERVERS {
        debug!("[STUN] DNS 解析: {}:{}", host, port);
        let addr = resolve_stun_addr(host, port);
        let Some(addr) = addr else {
            warn!("[STUN] 跳过 {}:{} (无 IPv4 地址)", host, port);
            continue;
        };

        match query_with_options(sock, addr, false, false) {
            Some(result) => {
                info!(
                    "[STUN] ✅ {} → {}:{} ({}ms)",
                    host, result.mapping.ip, result.mapping.port, result.rtt_ms
                );
                samples.push(StunServerSample {
                    server: format!("{}:{}", host, port),
                    mapping: result.mapping,
                    rtt_ms: result.rtt_ms,
                });
            }
            None => {
                warn!("[STUN] ❌ 查询失败: {} ({})", host, addr);
            }
        }

        std::thread::sleep(Duration::from_millis(180));
    }

    info!("[STUN] 查询完成，获得 {} 个映射", samples.len());
    samples
}

/// 用**服务端下发**的 STUN 列表在指定 socket 上采样。
///
/// 与旧的 [`query_all`] 有两点关键差别：
/// 1. 服务器列表来自服务端下发（自建优先），客户端不内置任何地址——
///    实测三台境外公共 STUN 曾在单次会话内全部超时，
///    而 STUN 一失败就拿不到 srflx 候选，必然落中继；
/// 2. **必须在同一个 socket 上顺序采样**，因为我们要观察的正是
///    "同一源端口对不同目标的映射变化"——这是判定 NAT 分类的依据，
///    换 socket 采样会让判定失去意义。
pub fn query_all_on(sock: &UdpSocket, servers: &[(String, u16)]) -> Vec<StunMapping> {
    let mut out = Vec::new();
    if servers.is_empty() {
        warn!("[STUN] 服务器列表为空（服务端尚未下发配置），无法探测映射");
        return out;
    }
    info!("[STUN] 开始采样 {} 个服务器", servers.len());
    for (host, port) in servers {
        let Some(addr) = resolve_stun_addr(host, *port) else {
            warn!("[STUN] 跳过 {}:{} (解析失败)", host, port);
            continue;
        };
        match query_with_options(sock, addr, false, false) {
            Some(r) => {
                info!(
                    "[STUN] ✅ {} → {}:{} ({}ms)",
                    host, r.mapping.ip, r.mapping.port, r.rtt_ms
                );
                out.push(r.mapping);
            }
            None => warn!("[STUN] ❌ 查询失败: {} ({})", host, addr),
        }
    }
    info!("[STUN] 采样完成，获得 {} 个映射", out.len());
    out
}

/// 在指定 socket 上取第一个成功的映射（用于新建 socket 的快速探测）。
///
/// 策略候选阶段可能要为几十个 socket 各探一次映射，
/// 逐个把整份列表跑完代价太高，命中一个即可。
pub fn query_first_on(sock: &UdpSocket, servers: &[(String, u16)]) -> Option<StunMapping> {
    for (host, port) in servers {
        let Some(addr) = resolve_stun_addr(host, *port) else {
            continue;
        };
        if let Some(r) = query_with_options(sock, addr, false, false) {
            return Some(r.mapping);
        }
    }
    None
}

/// 双 socket 检测结果
pub struct DualStunResult {
    /// Socket A 的映射结果
    pub mappings_a: Vec<StunMapping>,
    /// Socket B 的映射结果（不同源端口）
    pub mappings_b: Vec<StunMapping>,
    /// Socket A 的本地端口
    pub local_port_a: u16,
    /// Socket B 的本地端口
    pub local_port_b: u16,
    /// Socket A 的详细样本（含 RTT 与服务器）
    pub samples_a: Vec<StunServerSample>,
    /// Socket B 的详细样本（含 RTT 与服务器）
    pub samples_b: Vec<StunServerSample>,
}

/// 双 socket STUN 检测（RFC 5780 风格）
///
/// 用两个不同源端口的 UDP socket 分别查询同一组 STUN 服务器，
/// 通过比较两组映射结果可以更准确地判断 NAT 类型：
/// - 如果两个 socket 到同一 STUN 服务器的映射端口不同，确认是对称 NAT
/// - 如果同一 socket 到不同 STUN 服务器的端口相同，确认是锥形 NAT
/// - 注意：普通 Binding 流程无法准确区分 Full/Restricted/Port-Restricted 的过滤行为
pub async fn query_dual_async() -> DualStunResult {
    tokio::task::spawn_blocking(|| {
        let sock_a = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[STUN] 无法绑定 UDP socket A: {}", e);
                return DualStunResult {
                    mappings_a: vec![],
                    mappings_b: vec![],
                    local_port_a: 0,
                    local_port_b: 0,
                    samples_a: vec![],
                    samples_b: vec![],
                };
            }
        };
        let sock_b = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[STUN] 无法绑定 UDP socket B: {}", e);
                return DualStunResult {
                    mappings_a: vec![],
                    mappings_b: vec![],
                    local_port_a: 0,
                    local_port_b: 0,
                    samples_a: vec![],
                    samples_b: vec![],
                };
            }
        };

        let local_port_a = sock_a.local_addr().map(|a| a.port()).unwrap_or(0);
        let local_port_b = sock_b.local_addr().map(|a| a.port()).unwrap_or(0);

        println!(
            "[STUN] 双端口检测: Socket A={}, Socket B={}",
            local_port_a, local_port_b
        );

        // Socket A 查询所有 STUN 服务器
        println!("[STUN] === Socket A 检测 ===");
        let samples_a = query_all_detailed(&sock_a);
        let mappings_a = samples_a.iter().map(|s| s.mapping.clone()).collect();

        // Socket B 查询所有 STUN 服务器
        println!("[STUN] === Socket B 检测 ===");
        let samples_b = query_all_detailed(&sock_b);
        let mappings_b = samples_b.iter().map(|s| s.mapping.clone()).collect();

        DualStunResult {
            mappings_a,
            mappings_b,
            local_port_a,
            local_port_b,
            samples_a,
            samples_b,
        }
    })
    .await
    .unwrap_or(DualStunResult {
        mappings_a: vec![],
        mappings_b: vec![],
        local_port_a: 0,
        local_port_b: 0,
        samples_a: vec![],
        samples_b: vec![],
    })
}

pub async fn detect_filtering_behavior_async() -> FilteringProbeResult {
    tokio::task::spawn_blocking(|| {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                return FilteringProbeResult {
                    behavior: FilteringBehavior::Unknown,
                    detail: format!("无法绑定过滤探测 socket: {}", e),
                    server: "--".to_string(),
                }
            }
        };

        for &(host, port) in STUN_SERVERS {
            let Some(addr) = resolve_stun_addr(host, port) else {
                continue;
            };

            let baseline = query_with_options(&sock, addr, false, false);
            let Some(base) = baseline else {
                continue;
            };

            let cp = query_with_options(&sock, addr, false, true);
            let cib = query_with_options(&sock, addr, true, true);

            let has_alt = base.other_address.is_some() || base.changed_address.is_some();
            let cp_effective = cp
                .as_ref()
                .map(|r| r.responder_addr != base.responder_addr)
                .unwrap_or(false);
            let cib_effective = cib
                .as_ref()
                .map(|r| r.responder_addr != base.responder_addr)
                .unwrap_or(false);

            // 如果服务器不支持 change request（常见），继续换服务器
            if !has_alt && !cp_effective && !cib_effective {
                continue;
            }

            let behavior = if cp_effective && cib_effective {
                FilteringBehavior::EndpointIndependent
            } else if cp_effective && !cib_effective {
                FilteringBehavior::AddressDependent
            } else if !cp_effective {
                FilteringBehavior::AddressPortDependent
            } else {
                FilteringBehavior::Unknown
            };

            let detail =
                format!(
                "baseline={}, change-port={}, change-ip+port={}, source(base={}, cp={}, cib={})",
                base.mapping.port,
                if cp_effective { "pass" } else { "blocked/unsupported" },
                if cib_effective {
                    "pass"
                } else {
                    "blocked/unsupported"
                },
                base.responder_addr,
                cp.as_ref()
                    .map(|v| v.responder_addr.to_string())
                    .unwrap_or_else(|| "--".to_string()),
                cib.as_ref()
                    .map(|v| v.responder_addr.to_string())
                    .unwrap_or_else(|| "--".to_string())
            );

            return FilteringProbeResult {
                behavior,
                detail,
                server: format!("{}:{}", host, port),
            };
        }

        FilteringProbeResult {
            behavior: FilteringBehavior::Unknown,
            detail: "所有 STUN 服务器均不支持过滤行为探测（或网络拦截）".to_string(),
            server: "--".to_string(),
        }
    })
    .await
    .unwrap_or(FilteringProbeResult {
        behavior: FilteringBehavior::Unknown,
        detail: "过滤行为探测任务异常".to_string(),
        server: "--".to_string(),
    })
}
