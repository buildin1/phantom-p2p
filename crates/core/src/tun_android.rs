//! Android TUN，由 VpnService 建立、fd 经 JNI 交给 Rust。
//!
//! 与其它平台的根本差别：**设备不是这里创建的**。Android 不允许应用直接开
//! `/dev/net/tun`，虚拟网卡由系统的 `VpnService.Builder` 建立，地址、路由、MTU
//! 全部在 Kotlin 侧配置好，Rust 只拿到一个已经可读写的文件描述符。
//!
//! 因此本文件里 `create()` 不创建任何东西，它等的是 [`set_vpn_fd`] 把 fd 放进来。
//! 拿到之后 Android 就是普通 Linux：同一套 `AsyncFd` + `read`/`write`，
//! 与 `tun_linux.rs` 的读写路径逐行对应。
//!
//! # Kotlin 侧的契约
//!
//! 1. 从信令事件（`signal:room_created` / `signal:join_ok`）拿到 subnet 与
//!    virtual_ip 后调用 `VpnService.Builder`，**MTU 必须与 `tun_bridge::TUN_MTU`
//!    一致**，否则大包会被静默丢弃。
//! 2. `establish()` 拿到 `ParcelFileDescriptor` 后调用 **`detachFd()`**，把裸 fd
//!    交给 [`set_vpn_fd`]。所有权自此归 Rust，Kotlin **不要**再 close 它——
//!    重复 close 会关掉一个可能已被复用的 fd 号。
//! 3. 路由由 `Builder.addRoute()` 配置；[`PlatformTun::add_route`] 在此平台是空操作。

use crate::tun::TunError;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

/// 等待 Kotlin 交出 fd 的上限。
///
/// VpnService 首次启动会弹系统授权对话框，用户点确认可能要好几秒，
/// 所以这个窗口必须比“正常建立”宽裕得多。
const FD_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// 轮询间隔。见 [`take_fd`] 里关于为何不用 `Notify` 的说明。
const FD_POLL_INTERVAL: Duration = Duration::from_millis(50);

static PENDING_FD: OnceLock<Mutex<Option<OwnedFd>>> = OnceLock::new();

fn pending_fd() -> &'static Mutex<Option<OwnedFd>> {
    PENDING_FD.get_or_init(|| Mutex::new(None))
}

/// 把 VpnService 建立好的 fd 交给 Rust。由 JNI 层调用。
///
/// 传入的必须是 `ParcelFileDescriptor.detachFd()` 的结果——所有权转移到这里，
/// 由 `PlatformTun` 析构时关闭。
///
/// 若槽里已有一个未被取走的 fd（例如上一次连接失败后残留），会被替换并立即
/// 关闭，避免泄漏。
pub fn set_vpn_fd(fd: RawFd) {
    if fd < 0 {
        tracing::error!("[TUN] JNI 传入的 VPN fd 非法: {}", fd);
        return;
    }
    // Safety: 约定调用方传入的是 detachFd() 的结果，所有权已转移。
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let previous = pending_fd().lock().unwrap().replace(owned);
    if previous.is_some() {
        tracing::warn!("[TUN] 槽中存在未取走的旧 VPN fd，已丢弃");
    }
    tracing::info!("[TUN] 已收到 VpnService fd: {}", fd);
}

/// 取走待用的 fd，最多等 [`FD_WAIT_TIMEOUT`]。
///
/// 用轮询而不是 `Notify`：`set_vpn_fd` 由 JNI 线程调用，它与 `create()` 的先后
/// 顺序无法保证。`notify_waiters()` 只唤醒当时已在等待的任务，fd 先到就会丢唤醒；
/// 而 `notify_one()` 的permit 语义在重连场景下又容易残留。建立 TUN 是一次性的
/// 慢路径，50ms 的轮询延迟无关紧要，换来的是没有丢唤醒的可能。
async fn take_fd(timeout: Duration) -> Option<OwnedFd> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(fd) = pending_fd().lock().unwrap().take() {
            return Some(fd);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(FD_POLL_INTERVAL).await;
    }
}

/// VpnService 给的 fd 默认是阻塞的，而 `AsyncFd` 要求非阻塞——
/// 否则 `read` 会把整个 tokio worker 线程卡住直到有包到达。
fn set_nonblocking(fd: &OwnedFd) -> Result<(), TunError> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(TunError::CreateFailed(format!(
            "F_GETFL failed: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(TunError::CreateFailed(format!(
            "F_SETFL O_NONBLOCK failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    fd: Arc<AsyncFd<OwnedFd>>,
    closed: AtomicBool,
    /// 唤醒停在 `read_packet`/`write_packet` 里等 fd 就绪的任务，
    /// 让 `close()` 能立刻返回，而不是干等到下一个包到达（或永远等不到）。
    close_notify: Notify,
}

impl PlatformTun {
    /// 等待并接管 VpnService 的 fd。
    ///
    /// `netmask` 与 `mtu` 在此平台仅用于记录：真正生效的是 Kotlin 侧
    /// `VpnService.Builder` 的配置，Rust 无法在事后更改。
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let fd = take_fd(FD_WAIT_TIMEOUT).await.ok_or_else(|| {
            TunError::CreateFailed(format!(
                "等待 VpnService 交出 fd 超时（{}s）——检查 VPN 授权是否被拒绝",
                FD_WAIT_TIMEOUT.as_secs()
            ))
        })?;

        set_nonblocking(&fd)?;
        let async_fd = Arc::new(
            AsyncFd::new(fd)
                .map_err(|e| TunError::CreateFailed(format!("AsyncFd failed: {}", e)))?,
        );

        tracing::info!(
            "[TUN] Android device ready: {} {} netmask={} mtu={}（地址与 MTU 由 VpnService.Builder 配置）",
            name,
            address,
            netmask,
            mtu
        );
        Ok(Self {
            name: name.to_string(),
            address,
            fd: async_fd,
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        })
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
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
            let mut guard = tokio::select! {
                r = self.fd.writable() => r.map_err(|e| TunError::WriteFailed(e.to_string()))?,
                _ = self.close_notify.notified() => {
                    return Err(TunError::WriteFailed("device is closed".into()));
                }
            };
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

    /// 空操作：Android 的路由必须在 `establish()` **之前**由
    /// `VpnService.Builder.addRoute()` 声明，建立之后无法追加。
    pub async fn add_route(&self, prefix: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        tracing::debug!(
            "[TUN] Android 路由 {}/{} 由 VpnService.Builder 配置，此处跳过",
            prefix,
            prefix_len
        );
        Ok(())
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // 唤醒正停在 read/write 里的任务，让它们看到 closed 标志立刻返回，
        // 而不是无限期等待 fd 就绪。
        self.close_notify.notify_waiters();
    }
}
