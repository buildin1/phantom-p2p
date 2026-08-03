//! 会话运行时的 JNI 桥。
//!
//! 打洞、信令、隧道的全部编排住在 `phantom_core::runtime::SessionRuntime`，
//! 与桌面端、headless 端共用同一份实现。这里只做三件事：把 Kotlin 的调用转成
//! `invoke`、把运行时的事件回调给 Kotlin、以及把 VpnService 的 fd 递进 core。
//!
//! # Kotlin 侧对应
//!
//! ```text
//! class NativeSession {
//!     external fun nativeInit(logDir: String, dataDir: String): Boolean
//!     external fun nativeConnectSignal(url: String)
//!     external fun nativeInvoke(command: String, payloadJson: String): String
//!     external fun nativeSetVpnFd(fd: Int)
//!     external fun nativeShutdown()
//!     // 由 Rust 回调：
//!     fun onNativeEvent(event: String, dataJson: String) { ... }
//! }
//! ```
//!
//! **`nativeInvoke` 会阻塞到命令完成，必须在后台线程调用**——放主线程会卡 UI。

use crate::RUNTIME;
use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use phantom_core::runtime::{RuntimeHost, SessionRuntime};
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;

static SESSION: Lazy<Mutex<Option<Arc<SessionRuntime>>>> = Lazy::new(|| Mutex::new(None));

/// Android 宿主：事件走 JNI 回调，两个目录由 Kotlin 在初始化时给定。
struct AndroidHost {
    vm: JavaVM,
    object: GlobalRef,
    log_dir: PathBuf,
    data_dir: PathBuf,
}

impl RuntimeHost for AndroidHost {
    fn emit(&self, event: &str, data: Value) {
        // 运行时从 tokio 线程调用这里，那些线程没有附着到 JVM，必须先 attach。
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let payload = data.to_string();
        let (Ok(event_str), Ok(payload_str)) = (env.new_string(event), env.new_string(&payload))
        else {
            return;
        };
        // 失败不做任何处理：界面没接上不该影响连接流程本身。
        let _ = env.call_method(
            self.object.as_obj(),
            "onNativeEvent",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&JObject::from(event_str)),
                JValue::Object(&JObject::from(payload_str)),
            ],
        );
    }

    /// 必须是 `getExternalFilesDir()`（`/sdcard/Android/data/<pkg>/files/`）。
    /// 用内部存储的话未 root 的设备取不到日志，等于没有可观测性。
    fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }
}

fn jstring_to_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    env.get_string(value).ok().map(|s| s.into())
}

/// 把结果包成固定形状的 JSON，Kotlin 侧只需判 `ok`。
fn wrap_result(result: Result<Value, String>) -> String {
    match result {
        Ok(data) => serde_json::json!({ "ok": true, "data": data }).to_string(),
        Err(error) => serde_json::json!({ "ok": false, "error": error }).to_string(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_NativeSession_nativeInit(
    mut env: JNIEnv,
    this: JObject,
    log_dir: JString,
    data_dir: JString,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(log_dir), Some(data_dir)) = (
            jstring_to_string(&mut env, &log_dir),
            jstring_to_string(&mut env, &data_dir),
        ) else {
            return false;
        };
        let (Ok(vm), Ok(object)) = (env.get_java_vm(), env.new_global_ref(&this)) else {
            return false;
        };

        let host = Arc::new(AndroidHost {
            vm,
            object,
            log_dir: PathBuf::from(log_dir),
            data_dir: PathBuf::from(data_dir),
        });

        // SessionRuntime::new 会 tokio::spawn 采样任务，必须在运行时上下文里建，
        // 否则直接 panic——桌面端就是这么炸过一次的。
        match RUNTIME.block_on(async { SessionRuntime::new(host) }) {
            Ok(runtime) => {
                *SESSION.lock() = Some(runtime);
                true
            }
            Err(error) => {
                tracing::error!("[JNI] 运行时初始化失败: {}", error);
                false
            }
        }
    }));
    if result.unwrap_or(false) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_NativeSession_nativeConnectSignal(
    mut env: JNIEnv,
    _this: JObject,
    url: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(url) = jstring_to_string(&mut env, &url) else {
            return;
        };
        let Some(runtime) = SESSION.lock().clone() else {
            tracing::error!("[JNI] 尚未 nativeInit 就调用了 connectSignal");
            return;
        };
        RUNTIME.block_on(async move { runtime.connect_signal(url).await });
    }));
}

/// 转发一条命令。命令名与载荷键名跟桌面端、headless 端完全一致。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_NativeSession_nativeInvoke(
    mut env: JNIEnv,
    _this: JObject,
    command: JString,
    payload_json: JString,
) -> jstring {
    let output = catch_unwind(AssertUnwindSafe(|| {
        let Some(command) = jstring_to_string(&mut env, &command) else {
            return wrap_result(Err("命令名无效".to_string()));
        };
        let payload = jstring_to_string(&mut env, &payload_json)
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or(Value::Null);

        let Some(runtime) = SESSION.lock().clone() else {
            return wrap_result(Err("运行时尚未初始化".to_string()));
        };
        wrap_result(RUNTIME.block_on(async move { runtime.invoke(&command, payload).await }))
    }))
    .unwrap_or_else(|_| wrap_result(Err("native 调用 panic".to_string())));

    env.new_string(output)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// 交接 VpnService 建立好的 TUN 描述符。
///
/// 传入的必须是 `ParcelFileDescriptor.detachFd()` 的结果——所有权转移给 Rust，
/// Kotlin 之后不要再 close 它。契约详见 `phantom_core` 的 `tun_android` 模块。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_NativeSession_nativeSetVpnFd(
    _env: JNIEnv,
    _this: JObject,
    fd: jint,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // 该入口只在 Android 上存在，但本 crate 会被 workspace 检查为 host 目标
        // 编译一遍（CI 的 checks job），所以非 Android 下退化为空操作。
        #[cfg(target_os = "android")]
        phantom_core::tun::android_set_vpn_fd(fd);
        #[cfg(not(target_os = "android"))]
        let _ = fd;
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_NativeSession_nativeShutdown(
    _env: JNIEnv,
    _this: JObject,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = SESSION.lock().take() else {
            return;
        };
        RUNTIME.block_on(async move {
            let _ = runtime.invoke("disconnect_signal", Value::Null).await;
        });
    }));
}
