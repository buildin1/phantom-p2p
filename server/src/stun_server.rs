//! 自建 STUN 服务（RFC 5389 Binding + RFC 5780 单 IP 子集）
//!
//! # 为什么必须自建
//!
//! STUN 是打洞链路上**唯一不可绕过**的一环：拿不到 srflx 候选就没有公网映射，
//! 没有映射就无从谈起端口预测与撒网，只能落中继。
//! 实测三台境外公共 STUN 曾在单次会话内全部超时（`os error 10060`），
//! 也就是说打洞在开始之前就已经注定失败。
//!
//! # 为什么需要两个端口
//!
//! 判定 NAT 的**映射行为**至少需要两个不同的目标端点：客户端用同一个
//! 源 socket 分别向两个端口发 Binding Request，比较返回的映射端口——
//!
//! * 两次映射端口相同  → 端点无关映射（锥形）
//! * 两次映射端口不同  → 地址/端口相关映射（对称），再看步进是否线性
//!
//! 只有单个端点时这个判定做不出来，NAT 分类就只能靠猜。
//!
//! # 实现范围（RFC 5780 单 IP 子集）
//!
//! * Binding Request → Binding Response（XOR-MAPPED-ADDRESS + MAPPED-ADDRESS）；
//! * OTHER-ADDRESS / CHANGED-ADDRESS 通告备用端点（同 IP + 另一端口）——
//!   客户端由此得知本服务器支持哪些换端点测试；
//! * CHANGE-REQUEST 的 **change-port**：从备用端口的 socket 回包，
//!   供客户端探测入向过滤是否端口相关（RFC 5780 Test III）；
//! * CHANGE-REQUEST 的 **change-ip** 无法满足（单 IP 部署），此时从收包端口
//!   原样回包——客户端看响应源地址未变即知"不支持"，不会误判成"被过滤"。
//!   区分 ADM 型对称 NAT 所需的第二个 IP 由 `[stun].fallback_servers`
//!   配置第三方服务器提供。
//! * 不实现 TURN。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
const HEADER_LEN: usize = 20;

/// 启动 STUN 服务，在主端口与备用端口各监听一个 socket。
///
/// `public_ip` 是对外公布地址解析出的公网 IP，用于 OTHER-ADDRESS 通告；
/// 解析不出来时不通告（客户端会退回纯多端点比对，功能不受影响）。
pub async fn start(
    bind: &str,
    port: u16,
    alt_port: u16,
    public_ip: Option<IpAddr>,
) -> Result<(), String> {
    let mut socks = Vec::with_capacity(2);
    for (p, label) in [(port, "主"), (alt_port, "备用")] {
        let addr = format!("{}:{}", bind, p);
        let sock = UdpSocket::bind(&addr)
            .await
            .map_err(|e| format!("STUN 绑定 {} 失败: {}", addr, e))?;
        info!("[STUN] {}端口监听 {}", label, addr);
        socks.push(Arc::new(sock));
    }
    let (main_sock, alt_sock) = (socks.remove(0), socks.remove(0));
    match public_ip {
        Some(ip) => info!(
            "[STUN] RFC 5780 change-port 已启用，OTHER-ADDRESS 通告 {}:{}/{}",
            ip, port, alt_port
        ),
        None => warn!("[STUN] 公网 IP 未知，不通告 OTHER-ADDRESS（change-port 仍可用）"),
    }
    // 每个端口的响应里通告"另一个端口"作为备用端点
    tokio::spawn(serve(
        main_sock.clone(),
        alt_sock.clone(),
        public_ip.map(|ip| SocketAddr::new(ip, alt_port)),
    ));
    tokio::spawn(serve(
        alt_sock,
        main_sock,
        public_ip.map(|ip| SocketAddr::new(ip, port)),
    ));
    Ok(())
}

async fn serve(sock: Arc<UdpSocket>, alt_sock: Arc<UdpSocket>, other_addr: Option<SocketAddr>) {
    // STUN 消息很小，1500 足够容纳任何合法请求
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!("[STUN] 接收失败: {}", e);
                continue;
            }
        };
        let Some(req) = parse_binding_request(&buf[..n]) else {
            debug!(
                "[STUN] 丢弃来自 {} 的非法/非 Binding 请求 ({} 字节)",
                from, n
            );
            continue;
        };
        let response = build_binding_response(&req.txn, from, other_addr);
        // 反放大：响应体积必须不大于请求，否则会被当作放大攻击的反射器
        if response.len() > n.max(HEADER_LEN) * 4 {
            warn!("[STUN] 响应过大，丢弃（防放大）");
            continue;
        }
        // change-port：从备用端口回包（RFC 5780 Test III）。
        // change-ip 满足不了（单 IP），带该标志的请求一律从原端口回包。
        let sender = if req.change_port && !req.change_ip {
            &alt_sock
        } else {
            &sock
        };
        if let Err(e) = sender.send_to(&response, from).await {
            debug!("[STUN] 回复 {} 失败: {}", from, e);
        }
    }
}

/// 解析后的 Binding Request
#[derive(Debug, PartialEq, Eq)]
struct BindingRequest {
    txn: [u8; 12],
    change_ip: bool,
    change_port: bool,
}

/// 校验并解析 Binding Request，返回 transaction id 与 CHANGE-REQUEST 标志。
///
/// 严格校验能挡掉绝大多数误投包与探测流量：
/// 前两位必须为 0、magic cookie 必须匹配、长度必须自洽且 4 字节对齐。
fn parse_binding_request(pkt: &[u8]) -> Option<BindingRequest> {
    if pkt.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    if msg_type != BINDING_REQUEST {
        return None;
    }
    // STUN 消息最高两位必须为 0（用于与其它协议复用同一端口时区分）
    if pkt[0] & 0xC0 != 0 {
        return None;
    }
    let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if msg_len % 4 != 0 || HEADER_LEN + msg_len > pkt.len() {
        return None;
    }
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&pkt[8..20]);

    let mut change_ip = false;
    let mut change_port = false;
    let mut pos = HEADER_LEN;
    let end = HEADER_LEN + msg_len;
    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let attr_len = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]) as usize;
        if pos + 4 + attr_len > end {
            break;
        }
        if attr_type == ATTR_CHANGE_REQUEST && attr_len == 4 {
            let flags =
                u32::from_be_bytes([pkt[pos + 4], pkt[pos + 5], pkt[pos + 6], pkt[pos + 7]]);
            change_ip = flags & 0x04 != 0;
            change_port = flags & 0x02 != 0;
        }
        pos += 4 + ((attr_len + 3) & !3);
    }

    Some(BindingRequest {
        txn,
        change_ip,
        change_port,
    })
}

/// 构造 Binding Response。
///
/// 同时带 XOR-MAPPED-ADDRESS（RFC 5389，现代客户端用）
/// 和 MAPPED-ADDRESS（RFC 3489 遗留，部分老实现只认这个）。
/// XOR 编码的存在意义是防止沿途 NAT 设备"好心"改写载荷里的 IP。
///
/// `other` 为备用端点时以 OTHER-ADDRESS（RFC 5780）+ CHANGED-ADDRESS
/// （RFC 3489 遗留别名）双属性通告，兼顾新旧客户端。
/// 只对 IPv4 客户端通告：v4 全套 68 字节，正好压在 4 倍反放大预算之内；
/// v6 地址属性各多 12 字节会顶穿预算，而 v6 没有 NAT，通告了也没用。
fn build_binding_response(txn: &[u8; 12], from: SocketAddr, other: Option<SocketAddr>) -> Vec<u8> {
    let mut attrs: Vec<u8> = Vec::with_capacity(96);
    push_xor_mapped_address(&mut attrs, txn, from);
    push_mapped_address(&mut attrs, ATTR_MAPPED_ADDRESS, from);
    if from.is_ipv4() {
        if let Some(o) = other.filter(|o| o.is_ipv4()) {
            push_mapped_address(&mut attrs, ATTR_OTHER_ADDRESS, o);
            push_mapped_address(&mut attrs, ATTR_CHANGED_ADDRESS, o);
        }
    }

    let mut out = Vec::with_capacity(HEADER_LEN + attrs.len());
    out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txn);
    out.extend_from_slice(&attrs);
    out
}

/// 追加一个属性，并补齐到 4 字节对齐（STUN 要求）
fn push_attr(out: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    let pad = (4 - value.len() % 4) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// 以 MAPPED-ADDRESS 的明文编码写入任意地址型属性
/// （MAPPED-ADDRESS / OTHER-ADDRESS / CHANGED-ADDRESS 编码相同）
fn push_mapped_address(out: &mut Vec<u8>, attr_type: u16, addr: SocketAddr) {
    let mut v = Vec::with_capacity(20);
    v.push(0);
    match addr.ip() {
        IpAddr::V4(ip) => {
            v.push(0x01);
            v.extend_from_slice(&addr.port().to_be_bytes());
            v.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            v.push(0x02);
            v.extend_from_slice(&addr.port().to_be_bytes());
            v.extend_from_slice(&ip.octets());
        }
    }
    push_attr(out, attr_type, &v);
}

fn push_xor_mapped_address(out: &mut Vec<u8>, txn: &[u8; 12], addr: SocketAddr) {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut v = Vec::with_capacity(20);
    v.push(0);
    // 端口与 cookie 高 16 位异或
    let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match addr.ip() {
        IpAddr::V4(ip) => {
            v.push(0x01);
            v.extend_from_slice(&xport.to_be_bytes());
            let o = ip.octets();
            for i in 0..4 {
                v.push(o[i] ^ cookie[i]);
            }
        }
        IpAddr::V6(ip) => {
            v.push(0x02);
            v.extend_from_slice(&xport.to_be_bytes());
            let o = ip.octets();
            // IPv6 与 (cookie || transaction id) 逐字节异或
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(txn);
            for i in 0..16 {
                v.push(o[i] ^ key[i]);
            }
        }
    }
    push_attr(out, ATTR_XOR_MAPPED_ADDRESS, &v);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTR_SOFTWARE: u16 = 0x8022;

    fn make_request(txn: [u8; 12]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        p.extend_from_slice(&txn);
        p
    }

    fn make_change_request(txn: [u8; 12], change_ip: bool, change_port: bool) -> Vec<u8> {
        let mut p = make_request(txn);
        let mut flags = 0u32;
        if change_ip {
            flags |= 0x04;
        }
        if change_port {
            flags |= 0x02;
        }
        p.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&flags.to_be_bytes());
        p[2..4].copy_from_slice(&8u16.to_be_bytes());
        p
    }

    #[test]
    fn accepts_well_formed_binding_request() {
        let txn = [7u8; 12];
        assert_eq!(
            parse_binding_request(&make_request(txn)),
            Some(BindingRequest {
                txn,
                change_ip: false,
                change_port: false,
            })
        );
    }

    #[test]
    fn parses_change_request_flags() {
        let txn = [9u8; 12];
        let req = parse_binding_request(&make_change_request(txn, false, true)).unwrap();
        assert!(!req.change_ip);
        assert!(req.change_port);
        let req = parse_binding_request(&make_change_request(txn, true, true)).unwrap();
        assert!(req.change_ip);
        assert!(req.change_port);
    }

    #[test]
    fn rejects_wrong_magic_cookie() {
        let mut p = make_request([1u8; 12]);
        p[4] = 0xFF;
        assert!(parse_binding_request(&p).is_none());
    }

    #[test]
    fn rejects_non_binding_and_short_packets() {
        let mut p = make_request([1u8; 12]);
        p[1] = 0x02; // 不是 Binding Request
        assert!(parse_binding_request(&p).is_none());
        assert!(parse_binding_request(&[0u8; 8]).is_none());
    }

    #[test]
    fn rejects_packets_with_high_bits_set() {
        // 最高两位非 0 的不是 STUN——与其它协议复用端口时靠这个区分
        let mut p = make_request([1u8; 12]);
        p[0] |= 0x80;
        assert!(parse_binding_request(&p).is_none());
    }

    #[test]
    fn rejects_inconsistent_length() {
        let mut p = make_request([1u8; 12]);
        // 声称有 64 字节属性，实际一个都没有
        p[2..4].copy_from_slice(&64u16.to_be_bytes());
        assert!(parse_binding_request(&p).is_none());
    }

    /// XOR-MAPPED-ADDRESS 必须能被标准客户端正确还原，
    /// 否则客户端拿到的公网映射是错的，打洞会打向不存在的地址。
    #[test]
    fn xor_mapped_address_roundtrips() {
        let txn = [3u8; 12];
        let from: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let resp = build_binding_response(&txn, from, None);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), BINDING_RESPONSE);
        assert_eq!(&resp[8..20], &txn);

        // 定位 XOR-MAPPED-ADDRESS 属性并解码
        let mut i = HEADER_LEN;
        let mut decoded = None;
        while i + 4 <= resp.len() {
            let t = u16::from_be_bytes([resp[i], resp[i + 1]]);
            let l = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
            let v = &resp[i + 4..i + 4 + l];
            if t == ATTR_XOR_MAPPED_ADDRESS {
                let port = u16::from_be_bytes([v[2], v[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
                let c = MAGIC_COOKIE.to_be_bytes();
                let ip =
                    std::net::Ipv4Addr::new(v[4] ^ c[0], v[5] ^ c[1], v[6] ^ c[2], v[7] ^ c[3]);
                decoded = Some(SocketAddr::from((ip, port)));
                break;
            }
            i += 4 + l + (4 - l % 4) % 4;
        }
        assert_eq!(decoded, Some(from));
    }

    fn find_attr(resp: &[u8], want: u16) -> Option<Vec<u8>> {
        let mut i = HEADER_LEN;
        while i + 4 <= resp.len() {
            let t = u16::from_be_bytes([resp[i], resp[i + 1]]);
            let l = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
            if t == want {
                return Some(resp[i + 4..i + 4 + l].to_vec());
            }
            i += 4 + l + (4 - l % 4) % 4;
        }
        None
    }

    #[test]
    fn response_also_carries_legacy_mapped_address() {
        // 部分老实现只认 RFC 3489 的 MAPPED-ADDRESS
        let resp = build_binding_response(&[0u8; 12], "198.51.100.9:1234".parse().unwrap(), None);
        assert!(
            find_attr(&resp, ATTR_MAPPED_ADDRESS).is_some(),
            "响应应同时带 MAPPED-ADDRESS 以兼容老客户端"
        );
    }

    #[test]
    fn response_advertises_other_address_when_known() {
        // RFC 5780：客户端靠 OTHER-ADDRESS 得知备用端点，才敢做换端点测试；
        // 同时带 CHANGED-ADDRESS 供 RFC 3489 老客户端识别
        let other: SocketAddr = "203.0.113.1:3479".parse().unwrap();
        let resp = build_binding_response(
            &[0u8; 12],
            "198.51.100.9:1234".parse().unwrap(),
            Some(other),
        );
        let v = find_attr(&resp, ATTR_OTHER_ADDRESS).expect("应通告 OTHER-ADDRESS");
        assert_eq!(u16::from_be_bytes([v[2], v[3]]), 3479);
        assert_eq!(&v[4..8], &[203, 0, 113, 1]);
        assert!(find_attr(&resp, ATTR_CHANGED_ADDRESS).is_some());
    }

    #[test]
    fn attributes_are_four_byte_aligned() {
        // STUN 要求属性 4 字节对齐；用奇数长度验证补齐逻辑本身
        let mut out = Vec::new();
        push_attr(&mut out, ATTR_SOFTWARE, b"abc");
        assert_eq!(out.len() % 4, 0);
        assert_eq!(
            u16::from_be_bytes([out[2], out[3]]),
            3,
            "长度字段记录真实长度"
        );
    }

    #[test]
    fn response_is_not_larger_than_amplification_budget() {
        // 反放大：带 OTHER-ADDRESS + CHANGED-ADDRESS 的全量响应
        // 也必须压在最小请求的 4 倍以内
        let req = make_request([0u8; 12]);
        let resp = build_binding_response(
            &[0u8; 12],
            "1.2.3.4:1".parse().unwrap(),
            Some("203.0.113.1:3479".parse().unwrap()),
        );
        assert!(
            resp.len() <= req.len() * 4,
            "响应 {} 字节 vs 请求 {} 字节，放大比过高",
            resp.len(),
            req.len()
        );
    }
}
