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

/// 调优打洞 socket。
///
/// **放大接收缓冲区**是关键：撒网策略下瞬时到达速率很高，
/// 默认 64KB 缓冲区会在不到一秒内被填满，真正的应答包随之丢失。
///
/// Windows 上还必须关闭 `SIO_UDP_CONNRESET`——否则向不存在的端口发包
/// 收到 ICMP Port Unreachable 后，**后续的 `recv_from` 会返回 `WSAECONNRESET`**
/// 而不是正常数据，把接收路径彻底堵死。撒网场景下这几乎必然发生。
pub fn tune_punch_socket(sock: &UdpSocket) {
    const RECV_BUF: usize = 8 * 1024 * 1024;
    let s = socket2::SockRef::from(sock);
    if let Err(e) = s.set_recv_buffer_size(RECV_BUF) {
        tracing::debug!("[网络] 设置接收缓冲区失败: {}", e);
    }
    if let Err(e) = s.set_send_buffer_size(2 * 1024 * 1024) {
        tracing::debug!("[网络] 设置发送缓冲区失败: {}", e);
    }
    #[cfg(windows)]
    disable_udp_conn_reset(sock);
}

/// 关闭 Windows 的 `SIO_UDP_CONNRESET` 行为。
///
/// 默认情况下，未连接的 UDP socket 在收到 ICMP Port Unreachable 之后，
/// 下一次 `recvfrom` 会返回 `WSAECONNRESET (10054)` 而不是数据。
/// 打洞时我们会大量向不存在的端口发包，若不关掉这个行为，
/// 接收路径会被 ICMP 错误淹没。
#[cfg(windows)]
fn disable_udp_conn_reset(sock: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    const SIO_UDP_CONNRESET: u32 = 0x9800000C;

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const std::ffi::c_void,
            cbInBuffer: u32,
            lpvOutBuffer: *mut std::ffi::c_void,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
            lpCompletionRoutine: *mut std::ffi::c_void,
        ) -> i32;
    }

    let mut enable: u32 = 0; // FALSE = 禁用该行为
    let mut returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            &mut enable as *mut u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        tracing::debug!("[网络] 关闭 SIO_UDP_CONNRESET 失败, rc={}", rc);
    }
}

/// 枚举本机所有非回环 IPv4 地址（排除本产品自己的 overlay 网卡）
pub fn local_ipv4_addrs() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(list) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in list {
            if is_overlay_interface(&name) {
                continue;
            }
            if ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified() {
                let v = ip.to_string();
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// 枚举本机所有全局 IPv6 地址（排除链路本地、回环、组播与 overlay 网卡）
pub fn global_ipv6_addrs() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(list) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in list {
            if is_overlay_interface(&name) {
                continue;
            }
            let IpAddr::V6(v6) = ip else { continue };
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
            {
                continue;
            }
            let v = v6.to_string();
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

/// 是否为本产品自己创建的 overlay 网卡（必须排除，否则会把虚拟地址当候选上报）
pub fn is_overlay_interface(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("phantomp2p")
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
