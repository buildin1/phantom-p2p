//! Android JNI 导出面。
//!
//! # 边界在哪
//!
//! 这一层只做三件事：把 Java 类型翻成 Rust 类型、把 Rust 事件推回 Java、
//! 管住 `SessionRuntime` 的生命周期。**任何编排逻辑都不该出现在这里** ——
//! 那些在 [`runtime`] 里，引擎在 `phantom-core` 里。
//!
//! # 数据面不走这里
//!
//! 这里只有控制面：建房、入房、状态事件、统计、日志。IP 包**完全不经过 JNI**
//! —— `VpnService` 交出的 fd 直接由 `phantom-core` 的 `tun_android` 用
//! `AsyncFd` 读写。旧版本每个包都回调进 Kotlin 再送回 Rust，1160 字节 MTU
//! 下满速是每秒几万次往返，那是自己给自己造的性能坑。
//!
//! # 为什么手写 JNI 而不是 UniFFI
//!
//! iOS 暂时挂起，"一份接口生成双端绑定"这个理由不成立。手写少一个构建步骤、
//! CI 不用多装工具。等 iOS 回来再评估。

mod host;
mod runtime;

use host::{RuntimeHost, TunRequest};
use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::sys::{jboolean, jint, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use runtime::SessionRuntime;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

/// Tokio 运行时。
///
/// 4 个 worker：打洞阶段会有几十个 socket 并发收发，同时信令心跳、
/// 统计采样、QUIC 都在跑。线程太少的话一个阻塞点就能把整个运行时卡住 ——
/// 旧版本用 2 个线程，在中继场景下出现过整体卡死。
static TOKIO: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("phantom-engine")
        .build()
        .expect("创建 tokio 运行时失败")
});

/// 全局引擎。移动端同一时刻只可能有一条隧道（系统只允许一个活跃 VPN），
/// 所以不需要句柄表。
static ENGINE: Lazy<Mutex<Option<Arc<SessionRuntime>>>> = Lazy::new(|| Mutex::new(None));

/// JavaVM 只能取一次，之后任意线程都能靠它 attach 回 JVM。
static JVM: OnceCell<JavaVM> = OnceCell::new();

// ---------------------------------------------------------------------------
// 宿主实现：所有回调都打到 Kotlin 侧的 PhantomEngine 对象上
// ---------------------------------------------------------------------------

struct AndroidHost {
    callback: GlobalRef,
    log_dir: PathBuf,
    data_dir: PathBuf,
}

impl AndroidHost {
    /// 附着到当前线程并执行一段 JNI 操作。
    ///
    /// 引擎的回调来自 tokio 的 worker 线程，那些线程 JVM 并不认识，
    /// 必须先 attach。用 `attach_current_thread` 而不是 permanently 版本：
    /// worker 线程是长期存活的，permanently 会让它们永远挂在 JVM 上，
    /// 阻止 JVM 正常退出。
    fn with_env<T>(&self, f: impl FnOnce(&mut JNIEnv, &JObject) -> Option<T>) -> Option<T> {
        let vm = JVM.get()?;
        let mut env = vm.attach_current_thread().ok()?;
        let obj = self.callback.as_obj();
        f(&mut env, obj)
    }
}

impl RuntimeHost for AndroidHost {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        let payload = payload.to_string();
        self.with_env(|env, obj| {
            let event = env.new_string(event).ok()?;
            let payload = env.new_string(payload).ok()?;
            env.call_method(
                obj,
                "onEngineEvent",
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[JValue::Object(&event), JValue::Object(&payload)],
            )
            .ok()?;
            Some(())
        });
    }

    fn establish_tun(&self, request: &TunRequest) -> Result<i32, String> {
        // 路由编码成 "10.66.0.0/24,10.66.0.1/32"：JNI 传字符串数组要建
        // ObjectArray、逐个塞，为几条路由不值得。解析在 Kotlin 侧一行搞定。
        let routes = request
            .routes
            .iter()
            .map(|(addr, len)| format!("{}/{}", addr, len))
            .collect::<Vec<_>>()
            .join(",");

        self.with_env(|env, obj| {
            let address = env.new_string(&request.address).ok()?;
            let routes = env.new_string(&routes).ok()?;
            let fd = env
                .call_method(
                    obj,
                    "onEstablishTun",
                    "(Ljava/lang/String;ILjava/lang/String;I)I",
                    &[
                        JValue::Object(&address),
                        JValue::Int(request.prefix_len as jint),
                        JValue::Object(&routes),
                        JValue::Int(request.mtu as jint),
                    ],
                )
                .ok()?
                .i()
                .ok()?;
            Some(fd)
        })
        .ok_or_else(|| "JNI 调用 onEstablishTun 失败".to_string())
        .and_then(|fd| {
            if fd < 0 {
                Err("VpnService 建立虚拟网卡失败（用户可能拒绝了权限）".into())
            } else {
                Ok(fd)
            }
        })
    }

    fn protect_socket(&self, fd: i32) -> bool {
        self.with_env(|env, obj| {
            env.call_method(obj, "onProtectSocket", "(I)Z", &[JValue::Int(fd)])
                .ok()?
                .z()
                .ok()
        })
        .unwrap_or(false)
    }

    fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|v| v.into())
        .unwrap_or_else(|_| String::new())
}

/// 取当前引擎。没有就返回 None —— 所有导出函数都必须容忍这个，
/// Kotlin 侧的调用时机不完全受我们控制（比如 Service 被系统重启）。
fn engine() -> Option<Arc<SessionRuntime>> {
    ENGINE.lock().clone()
}

/// 把一次 JNI 调用包在 `catch_unwind` 里。
///
/// **Rust 的 panic 跨过 FFI 边界就是 abort** —— 整个应用直接闪退，用户
/// 看到的是「应用已停止」，什么线索都没有。这一层把 panic 变成一条日志
/// 加一个兜底返回值，至少让人能从日志里看出发生了什么。
///
/// 不是用它来掩盖 bug：panic 仍然会被完整记录，只是不再连坐整个进程。
fn guard<T>(what: &str, fallback: T, f: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    match std::panic::catch_unwind(f) {
        Ok(v) => v,
        Err(e) => {
            let msg = e
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "未知 panic".to_string());
            tracing::error!("[引擎] {} 发生 panic: {}", what, msg);
            fallback
        }
    }
}

/// 安装 panic 钩子，把 panic 写进日志文件。
///
/// 默认钩子只往 stderr 写，而 Android 上 stderr 是丢掉的 —— 界面按约定
/// 隐藏了链路的真实性质，日志是唯一的诊断入口，panic 必须落到那里。
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!("[引擎] panic: {}", info);
            previous(info);
        }));
    });
}

// ---------------------------------------------------------------------------
// 导出函数
//
// 命名必须与 Kotlin 侧 `com.buildin1.phantom_p2p.engine.PhantomEngine` 的
// external 声明逐字对应。改名要两边一起改，且 proguard-rules.pro 里有 keep。
// ---------------------------------------------------------------------------

/// 初始化引擎。返回 true 表示成功。
///
/// `callback` 是 Kotlin 侧的 PhantomEngine 实例，引擎会在它上面回调
/// `onEngineEvent` / `onEstablishTun` / `onProtectSocket`。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeInit(
    mut env: JNIEnv,
    _class: JObject,
    callback: JObject,
    log_dir: JString,
    data_dir: JString,
    dev_mode: jboolean,
) -> jboolean {
    let log_dir = PathBuf::from(jstring_to_string(&mut env, &log_dir));
    let data_dir = PathBuf::from(jstring_to_string(&mut env, &data_dir));

    if JVM.get().is_none() {
        match env.get_java_vm() {
            Ok(vm) => {
                let _ = JVM.set(vm);
            }
            Err(e) => {
                eprintln!("[phantom] 取 JavaVM 失败: {e}");
                return 0;
            }
        }
    }

    let callback = match env.new_global_ref(callback) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[phantom] 创建全局引用失败: {e}");
            return 0;
        }
    };

    // 日志必须最先起来：后面任何一步失败，唯一的线索就在日志里。
    // 目录走 getExternalFilesDir()，否则没 root 看不到。
    let _ = std::fs::create_dir_all(&log_dir);
    if let Err(e) = phantom_core::logging::init(&log_dir, dev_mode == JNI_TRUE) {
        eprintln!("[phantom] 日志初始化失败: {e}");
    }
    phantom_core::DEV_MODE.store(dev_mode == JNI_TRUE, std::sync::atomic::Ordering::Relaxed);
    install_panic_hook();

    let host = Arc::new(AndroidHost {
        callback,
        log_dir,
        data_dir,
    });

    // socket 保护钩子必须在任何 bind 之前注册 —— core 里十几处 bind
    // 分布在六个模块，漏一个那条路径的流量就会被自己的隧道吞掉。
    let guard_host = host.clone();
    phantom_core::socket_guard::set_protector(move |fd| guard_host.protect_socket(fd));

    // 必须先进 tokio 运行时上下文再构造。
    //
    // SessionRuntime::new 里会调 StatsManager::start_sampling_task()，
    // 那里面是 tokio::spawn —— 不在运行时上下文里调用会直接 panic，
    // 而 Rust 的 panic 跨过 FFI 边界就是 abort，表现为点「创建房间」
    // 应用闪退。这是生产测试里第一个暴露出来的问题。
    let _guard = TOKIO.enter();

    match SessionRuntime::new(host) {
        Ok(rt) => {
            *ENGINE.lock() = Some(rt);
            tracing::info!("[引擎] 初始化完成");
            1
        }
        Err(e) => {
            tracing::error!("[引擎] 初始化失败: {}", e);
            0
        }
    }
}

/// 连接信令服务器。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeConnectSignal(
    mut env: JNIEnv,
    _class: JObject,
    url: JString,
) {
    let url = jstring_to_string(&mut env, &url);
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        rt.connect_signal(url).await;
    });
}

/// 建房。房间码由服务端分配，通过 `signal:room_created` 事件回来。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeCreateRoom(
    _env: JNIEnv,
    _class: JObject,
) {
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        if let Err(e) = rt.create_room().await {
            tracing::error!("[引擎] 建房失败: {}", e);
        }
    });
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeJoinRoom(
    mut env: JNIEnv,
    _class: JObject,
    room_code: JString,
) {
    let code = jstring_to_string(&mut env, &room_code);
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        if let Err(e) = rt.join_room(code).await {
            tracing::error!("[引擎] 入房失败: {}", e);
        }
    });
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeLeaveRoom(
    _env: JNIEnv,
    _class: JObject,
) {
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        let _ = rt.leave_room().await;
    });
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeDisconnect(
    _env: JNIEnv,
    _class: JObject,
) {
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        rt.disconnect().await;
    });
}

/// 跑一次网络环境探测。结果通过 `net:profile` 事件回来。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeProbeNetwork(
    _env: JNIEnv,
    _class: JObject,
) {
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        if let Err(e) = rt.probe_network().await {
            tracing::warn!("[诊断] 网络探测失败: {}", e);
        }
    });
}

/// 请求上传日志（用户点「反馈问题」）。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeUploadLogs(
    mut env: JNIEnv,
    _class: JObject,
    reason: JString,
) {
    let reason = jstring_to_string(&mut env, &reason);
    let Some(rt) = engine() else { return };
    TOKIO.spawn(async move {
        if let Err(e) = rt.request_log_upload(reason).await {
            tracing::warn!("[引擎] 请求日志上传失败: {}", e);
        }
    });
}

/// 取一次统计快照，返回 JSON 字符串。
///
/// 用轮询而不是推送：统计本来就是秒级刷新的，推送要多维护一条事件通道，
/// 而界面只在可见时才需要它。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeStatsJson<'a>(
    env: JNIEnv<'a>,
    _class: JObject<'a>,
) -> JString<'a> {
    // 统计取不到时返回空对象而不是抛异常：这是每秒轮询一次的路径，
    // 偶发失败不该让界面崩掉，显示成「—」就够了。
    let json = guard("nativeStatsJson", String::from("{}"), || {
        let Some(rt) = engine() else {
            return String::from("{}");
        };
        // block_on 在这里是安全的：调用方是 Kotlin 的轮询协程，
        // 不是 tokio worker——在 worker 上 block_on 会死锁。
        let snapshot = TOKIO.block_on(async move { rt.stats_snapshot().await });
        serde_json::to_string(&snapshot).unwrap_or_else(|_| String::from("{}"))
    });

    env.new_string(json)
        .unwrap_or_else(|_| env.new_string("{}").expect("创建空 JSON 字符串失败"))
}

/// 隧道是否在跑。VpnService 用它决定前台通知的状态。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeIsTunnelLive(
    _env: JNIEnv,
    _class: JObject,
) -> jboolean {
    engine()
        .map(|rt| rt.is_tunnel_live() as jboolean)
        .unwrap_or(0)
}

/// 关停引擎。VpnService.onDestroy / onRevoke 时调用。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeShutdown(
    _env: JNIEnv,
    _class: JObject,
) {
    let Some(rt) = ENGINE.lock().take() else {
        return;
    };
    TOKIO.block_on(async move {
        rt.disconnect().await;
    });
    tracing::info!("[引擎] 已关停");
}

/// 引擎是否已初始化。进程被系统重建后 Kotlin 侧用它判断要不要重新 init。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeIsReady(
    _env: JNIEnv,
    _class: JObject,
) -> jboolean {
    ENGINE.lock().is_some() as jboolean
}

/// 保留：让 Kotlin 侧能显式丢弃一个已建但未被认领的 TUN fd。
/// 建隧道中途被取消时用，避免 fd 泄漏。
#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeDiscardTunFd(
    _env: JNIEnv,
    _class: JObject,
) {
    phantom_core::tun::android_discard_tun_fd();
}
