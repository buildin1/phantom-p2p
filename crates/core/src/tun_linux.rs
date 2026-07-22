//! Linux TUN implementation backed by `/dev/net/tun`.
//!
//! The process needs `CAP_NET_ADMIN` (or root) to create/configure the device.

use crate::tun::TunError;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    fd: Arc<AsyncFd<OwnedFd>>,
    closed: AtomicBool,
}

impl PlatformTun {
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(TunError::CreateFailed(format!(
                "open /dev/net/tun failed: {}",
                io::Error::last_os_error()
            )));
        }

        let mut ifr = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= IFNAMSIZ {
            unsafe { libc::close(fd) };
            return Err(TunError::CreateFailed("Linux TUN name is too long".into()));
        }
        for (idx, byte) in name_bytes.iter().enumerate() {
            ifr.name[idx] = *byte as libc::c_char;
        }

        let result = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr) };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TunError::CreateFailed(format!(
                "TUNSETIFF failed: {}",
                error
            )));
        }

        let actual_name = unsafe {
            std::ffi::CStr::from_ptr(ifr.name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = Arc::new(
            AsyncFd::new(owned)
                .map_err(|e| TunError::CreateFailed(format!("AsyncFd failed: {}", e)))?,
        );

        let prefix = netmask_to_prefix(netmask)?;
        run_ip(&["link", "set", "dev", &actual_name, "mtu", &mtu.to_string()])?;
        run_ip(&[
            "addr",
            "replace",
            &format!("{}/{}", address, prefix),
            "dev",
            &actual_name,
        ])?;
        run_ip(&["link", "set", "dev", &actual_name, "up"])?;

        tracing::info!(
            "[TUN] Linux device ready: {} {}/{} mtu={}",
            actual_name,
            address,
            prefix,
            mtu
        );
        Ok(Self {
            name: actual_name,
            address,
            fd: async_fd,
            closed: AtomicBool::new(false),
        })
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TunError::ReadFailed("device is closed".into()));
            }
            let guard = self
                .fd
                .readable()
                .await
                .map_err(|e| TunError::ReadFailed(e.to_string()))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Err(TunError::ReadFailed(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TunError::WriteFailed("device is closed".into()));
            }
            let guard = self
                .fd
                .writable()
                .await
                .map_err(|e| TunError::WriteFailed(e.to_string()))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Err(TunError::WriteFailed(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub async fn add_route(&self, prefix: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        run_ip(&[
            "route",
            "replace",
            &format!("{}/{}", prefix, prefix_len),
            "dev",
            &self.name,
            "scope",
            "link",
        ])
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

fn netmask_to_prefix(mask: Ipv4Addr) -> Result<u8, TunError> {
    let bits = u32::from_be_bytes(mask.octets());
    let prefix = bits.leading_ones() as u8;
    if bits
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        return Err(TunError::SetIpFailed(format!("invalid netmask {}", mask)));
    }
    Ok(prefix)
}

fn run_ip(args: &[&str]) -> Result<(), TunError> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| TunError::SetIpFailed(format!("run ip {:?}: {}", args, e)))?;
    if output.status.success() {
        return Ok(());
    }
    Err(TunError::SetIpFailed(format!(
        "ip {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
