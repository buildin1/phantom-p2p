//! Android TUN：接管 `VpnService` 建好的 fd。
//!
//! # 与其它平台的根本差别
//!
//! Windows / Linux / macOS 上 core 自己创建虚拟网卡。Android 上做不到 ——
//! 只有系统的 `VpnService` 有这个权限，它 `establish()` 之后返回一个
//! `ParcelFileDescriptor`，应用把裸 fd 交给我们。所以这里的 `create()`
//! **不创建任何东西**，它认领一个已经建好的 fd。
//!
//! # 为什么走 fd，不走逐包回调
//!
//! 拿到 fd 之后，读写就和 `tun_linux.rs` 完全一样：`AsyncFd` 直接在 fd 上
//! 收发，包不过 JNI。旧版本走的是另一条路 —— 每个包都回调进 Kotlin 再送回
//! Rust，1160 字节 MTU 下满速时是每秒几万次 JNI 往返。那是自己给自己造的
//! 性能坑，这里不重蹈覆辙。
//!
//! # 认领时序
//!
//! 房间的子网与本机虚拟 IP 由服务端在建房/入房时分配，所以 VpnService 必须
//! 等到那一步之后才能建网卡。流程是：
//!
//! 1. 引擎拿到子网分配，通过 JNI 回调让 `PhantomVpnService` 建立网卡
//! 2. Kotlin 侧 `establish()` 后 `detachFd()`，把裸 fd 通过 [`provide_fd`] 交进来
//! 3. `TunBridge::start` 走到 `TunDevice::create`，[`PlatformTun::create`] 认领它
//!
//! fd 的所有权在第 2 步转移给 Rust，关闭责任也一并转移（见 [`PlatformTun::close`]）。

use crate::tun::TunError;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

/// 等待被认领的 fd。
///
/// 用全局槽位而不是把 fd 一路传进 `TunBridge::start`：那要改动一个所有平台
/// 共用的签名，只为迁就一个平台的特殊性。这里的代价是同一时刻只能有一条
/// 隧道 —— 而移动端本来就只可能有一条（系统只允许一个活跃 VPN）。
static PENDING_FD: Mutex<Option<OwnedFd>> = Mutex::new(None);

/// 交入一个 `VpnService.establish()` 得到的裸 fd。
///
/// 调用方必须已经 `detachFd()`，即 Java 侧不再持有它 —— 否则两边都会 close，
/// 第二次 close 会作用到一个已被复用的 fd 上，那种 bug 极难追。
///
/// 如果槽位里还有上一条未被认领的 fd，会先关掉它并打日志：这说明上一次建隧道
/// 中途失败了，留下了泄漏。
pub fn provide_fd(fd: RawFd) {
    if fd < 0 {
        tracing::error!("[TUN] 收到非法 fd={}，忽略", fd);
        return;
    }
    // SAFETY: 调用方保证 fd 来自 detachFd()，所有权已转移，不会被 Java 侧再关。
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut slot = PENDING_FD.lock().expect("PENDING_FD 中毒");
    if let Some(stale) = slot.replace(owned) {
        tracing::warn!(
            "[TUN] 槽位里还有未认领的 fd={}，关掉它（上一次建隧道半途失败？）",
            stale.as_raw_fd()
        );
        drop(stale);
    }
}

/// 丢弃尚未被认领的 fd。建隧道中途失败时由宿主调用，避免泄漏。
pub fn discard_pending_fd() {
    if let Some(fd) = PENDING_FD.lock().expect("PENDING_FD 中毒").take() {
        tracing::info!("[TUN] 丢弃未认领的 fd={}", fd.as_raw_fd());
    }
}

pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    fd: Arc<AsyncFd<OwnedFd>>,
    closed: AtomicBool,
    /// 唤醒停在 `read_packet` / `write_packet` 里的任务，让 `close()` 能立刻返回，
    /// 而不是等到 fd 恰好可读为止（对端已经没了的话可能永远等不到）。
    close_notify: Notify,
}

impl PlatformTun {
    /// 认领 [`provide_fd`] 交进来的 fd。
    ///
    /// `netmask` 与 `mtu` 在这里被忽略 —— 它们已经在 Kotlin 侧
    /// `VpnService.Builder` 上设过了，系统不允许事后改。参数保留是为了
    /// 与其它平台保持同一个签名。
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        _netmask: Ipv4Addr,
        _mtu: u16,
    ) -> Result<Self, TunError> {
        let owned = PENDING_FD
            .lock()
            .expect("PENDING_FD 中毒")
            .take()
            .ok_or_else(|| {
                TunError::CreateFailed(
                    "没有待认领的 TUN fd —— VpnService 还没 establish，或者 fd 没交进来".into(),
                )
            })?;

        // AsyncFd 要求非阻塞，否则 read 会把整个 tokio worker 线程堵死。
        // VpnService 那边虽然调过 setBlocking(false)，但那是 Java 层的语义，
        // 这里再显式设一次，不依赖对面做对。
        set_nonblocking(owned.as_raw_fd())?;

        let async_fd = Arc::new(
            AsyncFd::new(owned).map_err(|e| TunError::CreateFailed(format!("AsyncFd: {e}")))?,
        );

        tracing::info!(
            "[TUN] Android 已认领 VpnService fd={} addr={}",
            async_fd.get_ref().as_raw_fd(),
            address
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

    /// Android 上路由由 `VpnService.Builder.addRoute()` 在建网卡时一次性设定，
    /// 建好之后无法追加。所以这里只记一条日志 —— 调用方需要的路由必须在
    /// establish 之前就通过 JNI 告诉 Kotlin 侧。
    pub async fn add_route(&self, prefix: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        tracing::debug!(
            "[TUN] Android 路由 {}/{} 由 VpnService.Builder 预设，此处忽略",
            prefix,
            prefix_len
        );
        Ok(())
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.close_notify.notify_waiters();
        // OwnedFd 随 self 一起析构时会 close(2)，不需要在这里手动关。
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), TunError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(TunError::CreateFailed(format!(
            "F_GETFL: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(TunError::CreateFailed(format!(
            "F_SETFL O_NONBLOCK: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}
