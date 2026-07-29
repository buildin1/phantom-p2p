//! Android does not expose a userspace TUN device to the Rust core.
//! The Android app owns the VPN interface and forwards packets through JNI.

use crate::tun::TunError;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    closed: AtomicBool,
    /// Kept for interface parity with the other platforms' cancellation
    /// mechanism. The Android app owns the actual VPN fd via JNI, so this
    /// stub never blocks in `read_packet`/`write_packet`, but a future real
    /// implementation (a blocking JNI read bridged onto a channel) should
    /// wire this the same way `tun_linux.rs`/`tun_windows.rs` do so `close()`
    /// can unblock it.
    #[allow(dead_code)]
    close_notify: Notify,
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
        self.close_notify.notify_waiters();
    }
}
