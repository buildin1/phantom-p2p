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
//!
//! # Privilege separation
//!
//! `com.apple.net.utun_control` is `CTL_FLAG_PRIVILEGED`: only a root
//! process can `connect()` to it, and assigning an address/MTU via
//! `ifconfig` likewise needs root. Running the whole GUI app as root just
//! to get this is a bad trade (root Cocoa/WebView processes are laggy and
//! can't be minimized/full-screened -- the BSD privilege context and the
//! Mach/WindowServer session end up out of sync). So the GUI process stays
//! unprivileged; [`provision`] (the only part that needs root) is instead
//! run inside a tiny separate helper binary (`crates/macos-helper`),
//! elevated on demand via `osascript ... with administrator privileges`,
//! which hands the already-configured fd back to the GUI process over a
//! Unix domain socket (`SCM_RIGHTS` fd passing, via the `passfd` crate).
//! The GUI process never runs as root; only the short-lived helper does.

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

/// A freshly opened and configured utun fd, plus the kernel-assigned
/// interface name, ready to be wrapped by [`PlatformTun::from_provisioned`].
/// Crossing a process boundary (helper -> GUI) is fine: it's just an owned
/// fd and a string.
pub struct ProvisionedTun {
    pub fd: OwnedFd,
    pub name: String,
}

/// Opens the utun control socket, connects it to a free unit, and assigns
/// its address/MTU via `ifconfig`. **Requires root** (see module docs) --
/// callers that aren't already root must go through the elevated helper
/// (see [`helper_client::request`]) instead of calling this directly.
pub fn provision(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> Result<ProvisionedTun, TunError> {
    let (fd, actual_name) = open_utun()?;

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
    run_command("ifconfig", &[&actual_name, "mtu", &mtu.to_string()])?;

    // Don't rely solely on the ifconfig same-address trick above to install
    // the on-link subnet route -- on some macOS versions/network configs it
    // doesn't reliably show up in the routing table, which silently drops
    // any reply headed back to another host in the subnet (the kernel never
    // hands the packet to this fd, so nothing shows up in app-level logs
    // either). Install it explicitly and treat failure as non-fatal: if the
    // ifconfig trick *did* already install it, this just errors out on a
    // duplicate route, which is fine.
    let network = Ipv4Addr::from(u32::from(address) & u32::from(netmask));
    let prefix_len = netmask.octets().iter().map(|o| o.count_ones()).sum::<u32>();
    if let Err(e) = run_command(
        "route",
        &[
            "-n",
            "add",
            "-net",
            &format!("{}/{}", network, prefix_len),
            "-interface",
            &actual_name,
        ],
    ) {
        tracing::warn!(
            "[TUN] 显式安装 {} 子网路由 {}/{} 失败（可能已由 ifconfig 隐式安装）: {}",
            actual_name,
            network,
            prefix_len,
            e
        );
    }

    Ok(ProvisionedTun {
        fd,
        name: actual_name,
    })
}

impl PlatformTun {
    /// Wraps an already-opened-and-configured utun fd (from [`provision`],
    /// called either in-process if already root, or by the elevated helper
    /// and handed back over a socket) into the async device. Needs no
    /// privilege of its own: the fd is already fully set up.
    fn from_provisioned(
        provisioned: ProvisionedTun,
        requested_name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        set_nonblocking(&provisioned.fd)?;
        let async_fd = Arc::new(
            AsyncFd::new(provisioned.fd)
                .map_err(|e| TunError::CreateFailed(format!("AsyncFd failed: {}", e)))?,
        );

        tracing::info!(
            "[TUN] macOS device ready: {} (requested name={}) {}/{} mtu={}",
            provisioned.name,
            requested_name,
            address,
            netmask,
            mtu
        );

        Ok(Self {
            name: provisioned.name,
            address,
            fd: async_fd,
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        })
    }

    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let provisioned = if unsafe { libc::geteuid() } == 0 {
            // Already root (e.g. a headless binary launched via `sudo`
            // directly): provision in-process, no helper needed.
            provision(address, netmask, mtu)?
        } else {
            // Not root: ask the small elevated helper to provision the
            // device and hand its fd back to us over a Unix socket.
            request_via_helper(address, netmask, mtu).await?
        };
        Self::from_provisioned(provisioned, name, address, netmask, mtu)
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

// ============================================================
// Elevated-helper client (GUI side): spawn `crates/macos-helper`
// with administrator privileges and receive its provisioned fd back
// over a Unix domain socket. See the module-level doc comment above
// for why this exists instead of running the whole app as root.
// ============================================================

/// Wire protocol on the helper -> GUI socket: one status byte, then either
/// (OK) the fd via `SCM_RIGHTS` followed by the interface name as UTF-8
/// text until EOF, or (ERR) the error message as UTF-8 text until EOF.
/// The status byte and the fd are deliberately never read with the same
/// plain `read()`/`write()` call that carries the fd: ancillary data
/// (`SCM_RIGHTS`) is only guaranteed to survive a `recvmsg()` call, so the
/// fd handoff always goes through `passfd`, and everything else uses plain
/// reads/writes on either side of it.
const HELPER_STATUS_OK: u8 = 1;
const HELPER_STATUS_ERR: u8 = 0;

fn helper_socket_path() -> std::path::PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("phantom-tun-{}-{}.sock", pid, nanos))
}

/// Locates the `phantom-macos-helper` sidecar binary Tauri bundles next to
/// the main executable (`bundle.externalBin` in `tauri.conf.json`). In
/// debug builds, also falls back to the helper crate's own `cargo build`
/// output so `cargo tauri dev`/`cargo run` work without a full bundle.
fn locate_helper_binary() -> Result<std::path::PathBuf, TunError> {
    let exe = std::env::current_exe()
        .map_err(|e| TunError::CreateFailed(format!("current_exe failed: {}", e)))?;
    let dir = exe
        .parent()
        .ok_or_else(|| TunError::CreateFailed("current_exe has no parent directory".to_string()))?;
    let bundled = dir.join("phantom-macos-helper");
    if bundled.exists() {
        return Ok(bundled);
    }

    #[cfg(debug_assertions)]
    {
        let dev_candidate =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/macos-helper");
        if dev_candidate.exists() {
            return Ok(dev_candidate);
        }
    }

    Err(TunError::CreateFailed(format!(
        "privileged helper not found (expected {}); build it with \
         `cargo build -p macos-helper` for local dev, or bundle it as a Tauri \
         sidecar for release builds",
        bundled.display()
    )))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn spawn_elevated_helper(
    socket_path: &std::path::Path,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> Result<tokio::process::Child, TunError> {
    let helper_path = locate_helper_binary()?;
    let args = [
        helper_path.to_string_lossy().into_owned(),
        socket_path.to_string_lossy().into_owned(),
        address.to_string(),
        netmask.to_string(),
        mtu.to_string(),
    ];
    let shell_cmd = args
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&shell_cmd)
    );

    tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| TunError::CreateFailed(format!("failed to launch privileged helper: {}", e)))
}

/// Asks the elevated helper to provision a utun device and hands its fd
/// back to us. See the module-level doc comment for the overall design.
async fn request_via_helper(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> Result<ProvisionedTun, TunError> {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    let socket_path = helper_socket_path();
    let _ = std::fs::remove_file(&socket_path); // best-effort stale-file cleanup
    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| TunError::CreateFailed(format!("bind helper socket failed: {}", e)))?;

    let mut child = spawn_elevated_helper(&socket_path, address, netmask, mtu)?;

    let accept_fut = tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept());
    tokio::pin!(accept_fut);

    let accept_result = tokio::select! {
        res = &mut accept_fut => res,
        status = child.wait() => {
            match status {
                Ok(s) if !s.success() => {
                    let _ = std::fs::remove_file(&socket_path);
                    return Err(TunError::CreateFailed(
                        "administrator authorization was cancelled or failed".to_string(),
                    ));
                }
                // Helper exited 0: it should already have connected and
                // sent everything; give the (already in-flight) connection
                // a brief grace period to surface in accept() rather than
                // erroring out immediately.
                _ => (&mut accept_fut).await,
            }
        }
    };
    let _ = std::fs::remove_file(&socket_path);

    let (mut stream, _) = accept_result
        .map_err(|_| TunError::CreateFailed("privileged helper timed out".to_string()))?
        .map_err(|e| TunError::CreateFailed(format!("accept failed: {}", e)))?;

    let mut status_byte = [0u8; 1];
    stream
        .read_exact(&mut status_byte)
        .await
        .map_err(|e| TunError::CreateFailed(format!("helper handshake failed: {}", e)))?;

    if status_byte[0] == HELPER_STATUS_ERR {
        let mut message = String::new();
        let _ = stream.read_to_string(&mut message).await;
        return Err(TunError::CreateFailed(format!(
            "privileged helper failed: {}",
            message.trim()
        )));
    }
    debug_assert_eq!(status_byte[0], HELPER_STATUS_OK);

    let mut std_stream = stream
        .into_std()
        .map_err(|e| TunError::CreateFailed(format!("into_std failed: {}", e)))?;
    std_stream
        .set_nonblocking(false)
        .map_err(|e| TunError::CreateFailed(format!("set_nonblocking failed: {}", e)))?;

    tokio::task::spawn_blocking(move || -> Result<ProvisionedTun, TunError> {
        use passfd::FdPassingExt;
        use std::io::Read;

        let raw_fd = std_stream
            .recv_fd()
            .map_err(|e| TunError::CreateFailed(format!("recv_fd failed: {}", e)))?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut name = String::new();
        std_stream
            .read_to_string(&mut name)
            .map_err(|e| TunError::CreateFailed(format!("read ifname failed: {}", e)))?;

        Ok(ProvisionedTun { fd, name })
    })
    .await
    .map_err(|e| TunError::CreateFailed(format!("helper task panicked: {}", e)))?
}
