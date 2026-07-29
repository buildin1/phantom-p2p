//! macOS TUN implementation backed by the kernel's `utun` control socket.
//!
//! macOS has no `/dev/net/tun`-style device; a userspace `utun` interface is
//! created by opening a `PF_SYSTEM`/`SYSPROTO_CONTROL` socket, resolving the
//! `com.apple.net.utun_control` kernel control id via `ioctl(CTLIOCGINFO)`,
//! then `connect()`-ing to it with a `sockaddr_ctl` whose `sc_unit` selects
//! (and, on success, names) the interface as `utun<sc_unit-1>`. This mirrors
//! the approach used by wireguard-go and Tailscale; no external crate is
//! needed, only raw syscalls via `libc`.
//!
//! Every packet read from / written to the resulting socket is prefixed
//! with a 4-byte, network-byte-order protocol family header (`AF_INET` = 2
//! or `AF_INET6` = 30) that must be stripped/added by this module.

use crate::tun::TunError;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

// ============================================================
// Kernel control socket plumbing (see <sys/kern_control.h>)
// ============================================================

const AF_SYSTEM: libc::c_int = 32;
const PF_SYSTEM: libc::c_int = AF_SYSTEM;
const SYSPROTO_CONTROL: libc::c_int = 2;
/// `ss_sysaddr` value identifying a kernel control socket address; shares
/// the numeric value of `SYSPROTO_CONTROL` but is a semantically distinct
/// field of `sockaddr_ctl`.
const AF_SYS_CONTROL: u16 = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const MAX_KCTL_NAME: usize = 96;
/// `_IOWR('N', 3, struct ctl_info)`, fixed for the 100-byte `ctl_info` on
/// all architectures Apple ships Rust toolchains for.
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
/// `getsockopt` option to fetch the kernel-assigned interface name
/// (e.g. "utun4") from a connected utun control socket.
const UTUN_OPT_IFNAME: libc::c_int = 2;
/// Highest `sc_unit` (1-based) to probe when looking for a free utun slot.
const MAX_UTUN_UNIT: u32 = 256;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; MAX_KCTL_NAME],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// Open a fresh utun control socket and connect it to the first free unit,
/// returning the raw fd and the kernel-assigned interface name.
fn open_utun() -> Result<(OwnedFd, String), TunError> {
    let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(TunError::CreateFailed(format!(
            "socket(PF_SYSTEM) failed: {}",
            io::Error::last_os_error()
        )));
    }
    // From here on, an early return must close `fd` to avoid leaking it.
    let guard = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0u8; MAX_KCTL_NAME],
    };
    info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
    let result = unsafe { libc::ioctl(guard.as_raw_fd(), CTLIOCGINFO, &mut info) };
    if result < 0 {
        return Err(TunError::CreateFailed(format!(
            "CTLIOCGINFO failed: {}",
            io::Error::last_os_error()
        )));
    }

    let mut last_error = io::Error::last_os_error();
    for unit in 1..=MAX_UTUN_UNIT {
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        let result = unsafe {
            libc::connect(
                guard.as_raw_fd(),
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if result == 0 {
            let name = read_ifname(&guard)?;
            return Ok((guard, name));
        }
        last_error = io::Error::last_os_error();
    }
    Err(TunError::CreateFailed(format!(
        "no free utun unit (last error: {})",
        last_error
    )))
}

fn read_ifname(fd: &OwnedFd) -> Result<String, TunError> {
    let mut name_buf = [0u8; 32];
    let mut len = name_buf.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name_buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(TunError::CreateFailed(format!(
            "UTUN_OPT_IFNAME failed: {}",
            io::Error::last_os_error()
        )));
    }
    let end = name_buf[..len as usize]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(len as usize);
    Ok(String::from_utf8_lossy(&name_buf[..end]).into_owned())
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), TunError> {
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0);
        if flags < 0 {
            return Err(TunError::CreateFailed(format!(
                "F_GETFL failed: {}",
                io::Error::last_os_error()
            )));
        }
        if libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(TunError::CreateFailed(format!(
                "F_SETFL O_NONBLOCK failed: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

// ============================================================
// Platform TUN implementation
// ============================================================

/// macOS `utun` implementation.
///
/// Unlike Linux, macOS assigns the interface name (`utun<N>`) at creation
/// time; the caller-supplied `name` is only used for logging.
pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    fd: Arc<AsyncFd<OwnedFd>>,
    closed: AtomicBool,
    /// Wakes any task parked in `read_packet`/`write_packet` so `close()`
    /// can return its callers promptly instead of leaving them blocked on
    /// the socket until unrelated traffic arrives (or forever).
    close_notify: Notify,
}

impl PlatformTun {
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let (fd, actual_name) = open_utun()?;
        set_nonblocking(&fd)?;
        let async_fd = Arc::new(
            AsyncFd::new(fd).map_err(|e| TunError::CreateFailed(format!("AsyncFd failed: {}", e)))?,
        );

        // utun interfaces are point-to-point by kernel default; assigning
        // the same address as both "local" and "peer" together with a real
        // netmask turns it into a normal on-link subnet route, matching how
        // tun_linux.rs configures its device via `ip addr`.
        run_command(
            "ifconfig",
            &[
                &actual_name,
                "inet",
                &address.to_string(),
                &address.to_string(),
                "netmask",
                &netmask.to_string(),
                "up",
            ],
        )?;
        run_command(
            "ifconfig",
            &[&actual_name, "mtu", &mtu.to_string()],
        )?;

        tracing::info!(
            "[TUN] macOS device ready: {} (requested name={}) {}/{} mtu={}",
            actual_name,
            name,
            address,
            netmask,
            mtu
        );

        Ok(Self {
            name: actual_name,
            address,
            fd: async_fd,
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        })
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        // utun sockets prefix every datagram with a 4-byte protocol family
        // header; read into a scratch buffer big enough for it and strip it
        // off before handing the IP packet back to the caller.
        let mut scratch = vec![0u8; buf.len() + 4];
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TunError::ReadFailed("device is closed".into()));
            }
            let mut guard = tokio::select! {
                r = self.fd.readable() => r.map_err(|e| TunError::ReadFailed(e.to_string()))?,
                _ = self.close_notify.notified() => {
                    return Err(TunError::ReadFailed("device is closed".into()));
                }
            };
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        scratch.as_mut_ptr().cast(),
                        scratch.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) if n >= 4 => {
                    let payload_len = n - 4;
                    buf[..payload_len].copy_from_slice(&scratch[4..n]);
                    return Ok(payload_len);
                }
                Ok(Ok(_)) => continue, // short read (just the family header, no payload)
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Err(TunError::ReadFailed(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        let family: u32 = match buf.first().map(|b| b >> 4) {
            Some(6) => libc::AF_INET6 as u32,
            _ => libc::AF_INET as u32,
        };
        let mut framed = Vec::with_capacity(buf.len() + 4);
        framed.extend_from_slice(&family.to_be_bytes());
        framed.extend_from_slice(buf);

        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TunError::WriteFailed("device is closed".into()));
            }
            let mut guard = tokio::select! {
                r = self.fd.writable() => r.map_err(|e| TunError::WriteFailed(e.to_string()))?,
                _ = self.close_notify.notified() => {
                    return Err(TunError::WriteFailed("device is closed".into()));
                }
            };
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        framed.as_ptr().cast(),
                        framed.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n.saturating_sub(4)),
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
        run_command(
            "route",
            &[
                "-n",
                "add",
                "-net",
                &format!("{}/{}", prefix, prefix_len),
                "-interface",
                &self.name,
            ],
        )
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.close_notify.notify_waiters();
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<(), TunError> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| TunError::SetIpFailed(format!("run {} {:?}: {}", program, args, e)))?;
    if output.status.success() {
        return Ok(());
    }
    Err(TunError::SetIpFailed(format!(
        "{} {:?} failed: {}",
        program,
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
