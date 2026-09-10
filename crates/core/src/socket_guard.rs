//! Socket 保护钩子。
//!
//! # 为什么需要它
//!
//! Android 上 `VpnService` 建立的隧道会接管本进程的**全部**出站流量，包括
//! 打洞用的 UDP socket 本身。结果是：打洞包被自己的隧道吞掉，发给对端的
//! 探测永远出不去，而隧道又要等打洞成功才能建起来 —— 死锁。
//!
//! 系统给的解法是 `VpnService.protect(fd)`：被保护的 socket 绕开隧道直接
//! 走物理网卡。所以 core 里**每一个** UDP socket 建好之后都必须过一遍这个
//! 钩子。core 里有十几处 `UdpSocket::bind`，分布在 `ice` / `network` /
//! `punch` / `stun` / `tunnel` / `udp_tunnel` 六个模块 —— 漏掉任何一处，
//! 那条路径上的流量就会静默消失，而且**只在真机上、只在隧道已建立之后**
//! 才会暴露，本地和 CI 都测不出来。
//!
//! # 设计取舍
//!
//! 用进程级全局钩子，而不是把 host 引用一路传进 punch/stun 的每个函数。
//! 传参更"干净"，但要改动几十个签名、且以后每加一个 bind 点都要重新穿一遍线；
//! 全局钩子只需要在 bind 之后加一行 [`protect`]。
//!
//! 桌面端不注册钩子，[`protect`] 就是空操作，零开销。

use std::sync::OnceLock;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

/// 宿主提供的保护函数。返回 false 表示保护失败（该 socket 会走进隧道）。
#[cfg(unix)]
type Protector = Box<dyn Fn(RawFd) -> bool + Send + Sync>;

#[cfg(unix)]
static PROTECTOR: OnceLock<Protector> = OnceLock::new();

/// 是否要求所有 socket 都必须被保护。
///
/// Android 上置为 true：此时任何未经保护的 socket 都会打出一条 ERROR 日志。
/// 这是唯一能让"漏了一处 bind"这类问题浮出水面的手段 —— 它不会让程序崩，
/// 但会在日志里留下确凿证据，而日志正是移动端唯一的诊断入口。
static STRICT: OnceLock<bool> = OnceLock::new();

/// 注册保护钩子。宿主在引擎启动前调用一次，重复调用会被忽略。
#[cfg(unix)]
pub fn set_protector<F>(f: F)
where
    F: Fn(RawFd) -> bool + Send + Sync + 'static,
{
    if PROTECTOR.set(Box::new(f)).is_err() {
        tracing::warn!("[socket] 保护钩子已注册过，忽略重复注册");
    }
    let _ = STRICT.set(true);
}

/// 保护一个已绑定的 socket，使其绕开本机 VPN 隧道。
///
/// 桌面端没有注册钩子，直接返回 true。
#[cfg(unix)]
pub fn protect<S: AsRawFd>(socket: &S) -> bool {
    let fd = socket.as_raw_fd();
    match PROTECTOR.get() {
        Some(f) => {
            let ok = f(fd);
            if !ok {
                tracing::error!("[socket] protect(fd={}) 失败，该 socket 会走进隧道", fd);
            }
            ok
        }
        None => {
            if *STRICT.get().unwrap_or(&false) {
                tracing::error!(
                    "[socket] fd={} 未经保护就绑定了 —— 这条路径漏了 socket_guard::protect",
                    fd
                );
            }
            true
        }
    }
}

/// 非 Unix 平台（Windows）没有这个问题，保留同名空实现让调用点不必加 cfg。
#[cfg(not(unix))]
pub fn protect<S>(_socket: &S) -> bool {
    true
}

#[cfg(not(unix))]
pub fn set_protector<F: 'static>(_f: F) {}
