//! macOS 平台 TUN 实现存根
//!
//! 当前返回 PlatformNotSupported，待后续实现 utun 接口调用。

use crate::tun::TunError;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

/// macOS 平台 TUN 存根
pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    closed: AtomicBool,
}

impl PlatformTun {
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        _netmask: Ipv4Addr,
        _mtu: u16,
    ) -> Result<Self, TunError> {
        let _ = (name, address);
        Err(TunError::PlatformNotSupported)
    }

    pub async fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, TunError> {
        Err(TunError::PlatformNotSupported)
    }

    pub async fn write_packet(&self, _buf: &[u8]) -> Result<usize, TunError> {
        Err(TunError::PlatformNotSupported)
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub async fn add_route(&self, _prefix: Ipv4Addr, _prefix_len: u8) -> Result<(), TunError> {
        Err(TunError::PlatformNotSupported)
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}
