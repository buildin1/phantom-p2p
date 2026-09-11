package com.buildin1.phantom_p2p.engine

import android.util.Log
import com.buildin1.phantom_p2p.vpn.PhantomVpnService
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import java.lang.ref.WeakReference

/**
 * JNI 桥。
 *
 * ## 命名必须与 Rust 侧逐字对应
 *
 * `crates/mobile/src/lib.rs` 里导出的符号是
 * `Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeXxx`
 * （`_1` 是 JNI 对包名里下划线的转义）。这个类的**包名、类名、方法名**任何
 * 一处改动都要两边同时改，否则是运行时 `UnsatisfiedLinkError` —— 编译期
 * 抓不到。`proguard-rules.pro` 里也有对应的 keep。
 *
 * ## 数据面不经过这里
 *
 * 这里只有控制面。IP 包由 Rust 侧直接在 `VpnService` 的 fd 上收发，
 * 一个字节都不过 JNI。
 */
object PhantomEngine {

    private const val TAG = "PhantomEngine"

    @Volatile
    private var libraryLoaded = false

    /**
     * 当前运行中的 VpnService。
     *
     * Rust 侧要建虚拟网卡时会回调到这里，而只有 Service 实例能调
     * `establish()` / `protect()`。用弱引用：Service 被系统销毁后
     * 这里不该拖住它。
     */
    private var serviceRef = WeakReference<PhantomVpnService>(null)

    /**
     * 引擎事件流。
     *
     * `extraBufferCapacity` 给得比较宽：打洞阶段事件很密集，而订阅方
     * （界面）可能正好在后台。`DROP_OLDEST` 是刻意的 —— 事件流里每一条
     * 都是状态快照的增量，丢最旧的那条比阻塞 Rust 的回调线程好得多。
     */
    private val _events = MutableSharedFlow<EngineEvent>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<EngineEvent> = _events

    fun attachService(service: PhantomVpnService?) {
        serviceRef = WeakReference(service)
    }

    /** 加载动态库。失败返回 false —— 没有 .so 时整个引擎不可用，但不该崩。 */
    fun ensureLibraryLoaded(): Boolean {
        if (libraryLoaded) return true
        return try {
            System.loadLibrary("phantom_mobile")
            libraryLoaded = true
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "加载 phantom_mobile 失败：APK 里可能没打进 .so", e)
            false
        }
    }

    // -----------------------------------------------------------------------
    // Rust 回调进来的三个入口
    //
    // 这三个方法由 Rust 的 tokio worker 线程调用，**不在主线程上**。
    // 里面不要碰任何要求主线程的 API。
    // -----------------------------------------------------------------------

    /** 引擎事件。`payload` 是 JSON 字符串。 */
    @Suppress("unused") // 由 JNI 调用
    fun onEngineEvent(event: String, payload: String) {
        _events.tryEmit(EngineEvent(event, payload))
    }

    /**
     * 建立虚拟网卡，返回已 detach 的裸 fd；失败返回 -1。
     *
     * `routes` 形如 `"10.66.0.0/24,10.66.0.1/32"` —— 为几条路由建
     * ObjectArray 不值得，Rust 侧拼串、这里拆开。
     *
     * **fd 的所有权在返回那一刻转移给 Rust**，这边不能再持有或关闭它。
     */
    @Suppress("unused") // 由 JNI 调用
    fun onEstablishTun(address: String, prefixLen: Int, routes: String, mtu: Int): Int {
        val service = serviceRef.get()
        if (service == null) {
            Log.e(TAG, "要建虚拟网卡但 VpnService 不在，权限流程可能没走完")
            return -1
        }
        val parsed = routes.split(',')
            .mapNotNull { entry ->
                val parts = entry.trim().split('/')
                if (parts.size != 2) return@mapNotNull null
                val prefix = parts[1].toIntOrNull() ?: return@mapNotNull null
                PhantomVpnService.Route(parts[0], prefix)
            }
        return service.establishTunnel(address, prefixLen, parsed, mtu)
    }

    /** 让一个 socket 绕开本机隧道。漏掉任何一个，那条路径的流量会被隧道吞掉。 */
    @Suppress("unused") // 由 JNI 调用
    fun onProtectSocket(fd: Int): Boolean {
        val service = serviceRef.get() ?: return false
        return service.protectSocket(fd)
    }

    // -----------------------------------------------------------------------
    // 导出给 Rust 的原生方法
    // -----------------------------------------------------------------------

    external fun nativeInit(
        callback: Any,
        logDir: String,
        dataDir: String,
        devMode: Boolean,
    ): Boolean

    external fun nativeConnectSignal(url: String)
    external fun nativeCreateRoom()
    external fun nativeJoinRoom(roomCode: String)

    /** 索要邀请令牌；`refresh` 为 true 时先作废旧的。结果走 `signal:invite_token`。 */
    external fun nativeRequestInviteToken(refresh: Boolean)

    /** 用邀请令牌加入房间（扫码 / 深链进来的路径）。 */
    external fun nativeJoinByToken(token: String)
    external fun nativeLeaveRoom()
    external fun nativeDisconnect()
    external fun nativeProbeNetwork()
    external fun nativeUploadLogs(reason: String)
    external fun nativeStatsJson(): String
    external fun nativeIsTunnelLive(): Boolean
    external fun nativeShutdown()
    external fun nativeIsReady(): Boolean
    external fun nativeDiscardTunFd()

    /** 初始化引擎。`this` 作为回调对象传过去。 */
    fun init(logDir: String, dataDir: String, devMode: Boolean): Boolean {
        if (!ensureLibraryLoaded()) return false
        if (nativeIsReady()) return true
        return nativeInit(this, logDir, dataDir, devMode)
    }
}

/** 一条引擎事件。`payload` 是未解析的 JSON。 */
data class EngineEvent(val name: String, val payload: String)
