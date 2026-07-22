//! 网络工具模块 —— 本机 IP、IPv6、UPnP 检测
//!
//! 跨平台：使用标准 socket API + igd-next crate

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

/// Bind one UDP socket that can carry native IPv6 and IPv4-mapped traffic.
pub fn bind_dual_stack_udp(port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    let socket: UdpSocket = socket.into();
    Ok(socket)
}

/// Convert an IPv4 destination for an AF_INET6 dual-stack socket.
pub fn compatible_socket_addr(socket: &UdpSocket, addr: SocketAddr) -> SocketAddr {
    if socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false) {
        if let SocketAddr::V4(v4) = addr {
            return SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0));
        }
    }
    addr
}

/// 获取本机局域网 IPv4 地址
///
/// 使用 UDP connect 技巧：连接到公网地址（不会真的发数据），
/// 然后获取 socket 的本地地址。比 `local-ip-address` crate 更可靠。
pub fn get_local_ip() -> String {
    // 尝试通过 UDP connect 获取
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        // 连接到 Google DNS，不会真正发送数据
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }

    // Fallback: 使用 local-ip-address crate
    match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "127.0.0.1".to_string(),
    }
}

/// 检测 IPv6 是否可用，返回 (可用, IPv6 地址)
pub fn detect_ipv6() -> (bool, String) {
    // 尝试创建 IPv6 UDP socket 并连接到公网 IPv6 地址
    let addr: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        53,
    );

    let bind_addr: SocketAddr = SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

    match UdpSocket::bind(bind_addr) {
        Ok(sock) => {
            if sock.connect(addr).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let ip_str = local.ip().to_string();
                    // 排除链路本地地址
                    if !ip_str.starts_with("fe80") && !ip_str.starts_with("::1") {
                        return (true, ip_str);
                    }
                }
            }
            (false, String::new())
        }
        Err(_) => (false, String::new()),
    }
}

/// UPnP 检测结果
pub struct UpnpResult {
    pub available: bool,
    pub external_port: u16,
}

/// 检测 UPnP 网关是否可用（不做端口映射，只检测能力）
///
/// 使用 igd-next crate 搜索网关设备，超时 3 秒
pub async fn detect_upnp() -> UpnpResult {
    tokio::task::spawn_blocking(|| {
        use igd_next::SearchOptions;
        use std::time::Duration;

        let opts = SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        };

        match igd_next::search_gateway(opts) {
            Ok(gateway) => {
                println!("[UPnP] 发现网关: {}", gateway.addr);
                // 只检测网关是否存在，不做映射
                UpnpResult {
                    available: true,
                    external_port: 0,
                }
            }
            Err(e) => {
                eprintln!("[UPnP] 未发现网关: {}", e);
                UpnpResult {
                    available: false,
                    external_port: 0,
                }
            }
        }
    })
    .await
    .unwrap_or(UpnpResult {
        available: false,
        external_port: 0,
    })
}

/// 同步获取所有本地网络信息（用于 spawn_blocking 环境）
pub struct LocalNetworkInfo {
    pub local_ip: String,
    pub ipv6_available: bool,
    pub ipv6_addr: String,
}

pub fn detect_local_network() -> LocalNetworkInfo {
    let local_ip = get_local_ip();
    let (ipv6_available, ipv6_addr) = detect_ipv6();

    LocalNetworkInfo {
        local_ip,
        ipv6_available,
        ipv6_addr,
    }
}
