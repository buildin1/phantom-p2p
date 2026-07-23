//! 虚拟网卡（TUN）模块
//!
//! 跨平台抽象：Windows 使用 wintun，macOS/Linux 使用系统 utun/tun。
//! 提供统一的 TUN 设备接口，支持 IP 包读写。

use std::net::Ipv4Addr;
use std::sync::Arc;

/// TUN 设备错误
#[derive(Debug)]
pub enum TunError {
    CreateFailed(String),
    ReadFailed(String),
    WriteFailed(String),
    SetIpFailed(String),
    PlatformNotSupported,
}

impl std::fmt::Display for TunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunError::CreateFailed(msg) => write!(f, "创建 TUN 设备失败: {}", msg),
            TunError::ReadFailed(msg) => write!(f, "读取 TUN 设备失败: {}", msg),
            TunError::WriteFailed(msg) => write!(f, "写入 TUN 设备失败: {}", msg),
            TunError::SetIpFailed(msg) => write!(f, "设置 IP 地址失败: {}", msg),
            TunError::PlatformNotSupported => write!(f, "当前平台不支持 TUN 设备"),
        }
    }
}

impl std::error::Error for TunError {}

/// IPv4 包头部（20 字节，无选项）
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv4Header {
    pub version_ihl: u8,      // 版本(4) + 头部长度(4)
    pub dscp_ecn: u8,         // 差分服务
    pub total_length: u16,    // 总长度（大端）
    pub identification: u16,  // 标识
    pub flags_fragment: u16,  // 标志 + 片偏移
    pub ttl: u8,              // 生存时间
    pub protocol: u8,         // 协议（6=TCP, 17=UDP）
    pub header_checksum: u16, // 头部校验和
    pub source: [u8; 4],      // 源 IP
    pub destination: [u8; 4], // 目标 IP
}

impl Ipv4Header {
    /// 从字节切片解析 IPv4 头部
    pub fn from_bytes(data: &[u8]) -> Option<&Ipv4Header> {
        if data.len() < 20 {
            return None;
        }
        // 验证版本号为 4
        if (data[0] >> 4) != 4 {
            return None;
        }
        Some(unsafe { &*(data.as_ptr() as *const Ipv4Header) })
    }

    /// 获取目标 IP 地址
    pub fn destination_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
        )
    }

    /// 获取源 IP 地址
    pub fn source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],
        )
    }

    /// 获取目标端口（需要 data 包含完整的 TCP/UDP 头部）
    pub fn destination_port(data: &[u8]) -> Option<u16> {
        let header_len = ((data[0] & 0x0f) * 4) as usize;
        if data.len() < header_len + 4 {
            return None;
        }
        Some(u16::from_be_bytes([
            data[header_len + 2],
            data[header_len + 3],
        ]))
    }

    /// 获取源端口
    pub fn source_port(data: &[u8]) -> Option<u16> {
        let header_len = ((data[0] & 0x0f) * 4) as usize;
        if data.len() < header_len + 4 {
            return None;
        }
        Some(u16::from_be_bytes([data[header_len], data[header_len + 1]]))
    }
}

/// 平台 TUN 设备（平台特定实现隐藏在此 trait 后）
#[cfg_attr(target_os = "windows", path = "tun_windows.rs")]
#[cfg_attr(target_os = "linux", path = "tun_linux.rs")]
#[cfg_attr(target_os = "macos", path = "tun_macos.rs")]
#[cfg_attr(target_os = "android", path = "tun_android.rs")]
mod platform;

/// TUN 设备
pub struct TunDevice {
    inner: Arc<platform::PlatformTun>,
}

impl TunDevice {
    /// 创建并配置 TUN 设备
    ///
    /// `name`: 设备名（各平台含义不同，Windows 下会忽略）
    /// `address`: 分配给设备的 IP 地址
    /// `netmask`: 子网掩码
    /// `mtu`: MTU 大小
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let inner = platform::PlatformTun::create(name, address, netmask, mtu).await?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// 读取一个 IP 包
    ///
    /// 返回 (包数据, 包长度)
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.inner.read_packet(buf).await
    }

    /// 写入一个 IP 包
    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        self.inner.write_packet(buf).await
    }

    /// 获取设备名称
    pub fn name(&self) -> String {
        self.inner.name()
    }

    /// 获取分配给设备的 IP 地址
    pub fn address(&self) -> Ipv4Addr {
        self.inner.address()
    }

    /// Route an Overlay prefix through this TUN device.
    pub async fn add_route(&self, prefix: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        self.inner.add_route(prefix, prefix_len).await
    }

    /// 关闭 TUN 设备
    pub async fn close(&self) {
        self.inner.close().await;
    }
}
