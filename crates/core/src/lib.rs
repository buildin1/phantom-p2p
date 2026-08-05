//! phantom-core — 平台无关的 P2P 引擎核心库
//!
//! 包含 NAT 检测、STUN、ICE、打洞、隧道、信令等所有引擎模块。
//! 不依赖 Tauri，可在 PC（src-tauri）和 Android（android-jni）中复用。

use std::sync::atomic::{AtomicBool, Ordering};

/// 全局开发者模式标志（由宿主进程在启动时设置）
pub static DEV_MODE: AtomicBool = AtomicBool::new(false);

static RUSTLS_PROVIDER_READY: AtomicBool = AtomicBool::new(false);

pub fn ensure_rustls_crypto_provider() -> Result<(), String> {
    if RUSTLS_PROVIDER_READY.load(Ordering::Acquire) {
        return Ok(());
    }

    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => {
            RUSTLS_PROVIDER_READY.store(true, Ordering::Release);
            Ok(())
        }
        Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => {
            RUSTLS_PROVIDER_READY.store(true, Ordering::Release);
            Ok(())
        }
        Err(_) => Err("安装 rustls CryptoProvider 失败".to_string()),
    }
}

pub mod config;
pub mod crypto;
pub mod fec;
pub mod ice;
pub mod identity;
pub mod log_upload;
pub mod logging;
pub mod nat;
pub mod network;
pub mod network_info;
pub mod punch;
pub mod puncher;
pub mod runtime;
pub mod signal;
pub mod stats;
pub mod stun;
pub mod tun;
pub mod tun_bridge;
pub mod tunnel;
pub mod udp_tunnel;
