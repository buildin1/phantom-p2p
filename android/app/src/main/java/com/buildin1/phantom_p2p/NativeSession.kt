package com.buildin1.phantom_p2p

import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * `phantom_core::runtime::SessionRuntime` 的 Kotlin 门面。
 *
 * 信令、STUN、NAT 分类、三阶段打洞、隧道与中继回退全部在 Rust 侧执行，
 * 与桌面端、headless 端是同一份实现。Kotlin 只负责发命令和收事件。
 *
 * 命令名与载荷键名跟另外两端**完全一致**——三端共用一个命令词表，
 * 不是三套各写各的。
 */
object NativeSession {

    private const val TAG = "NativeSession"

    init {
        runCatching { System.loadLibrary("phantom_mobile") }
            .onFailure { Log.e(TAG, "加载 phantom_mobile 失败", it) }
    }

    /** 运行时事件的订阅者。事件在 Rust 的 tokio 线程上回调，实现里不要做耗时操作。 */
    fun interface EventListener {
        fun onEvent(event: String, data: JSONObject)
    }

    @Volatile
    private var listener: EventListener? = null

    @Volatile
    private var initialized = false

    fun setListener(value: EventListener?) {
        listener = value
    }

    /**
     * 初始化运行时。**必须在 [IdentityMigration.migrateIfNeeded] 之后调用**——
     * 否则 Rust 找不到 identity.key 会静默生成新身份，用户的 user_id 就变了。
     *
     * @param logDir 必须是 `getExternalFilesDir()` 下的目录：内部存储未 root 读不到，
     *   而界面按设计不显示是否走中继，日志是判断真实链路的唯一途径。
     */
    @Synchronized
    fun init(logDir: File, dataDir: File): Boolean {
        if (initialized) return true
        logDir.mkdirs()
        dataDir.mkdirs()
        initialized = nativeInit(logDir.absolutePath, dataDir.absolutePath)
        if (!initialized) {
            Log.e(TAG, "运行时初始化失败")
        }
        return initialized
    }

    fun connectSignal(url: String) {
        if (!initialized) {
            Log.e(TAG, "尚未 init 就调用 connectSignal")
            return
        }
        nativeConnectSignal(url)
    }

    /**
     * 转发一条命令，阻塞到完成。
     *
     * **必须在后台线程调用**——底层会 block 到 Rust 侧的异步操作结束，
     * 放在主线程会卡住界面。
     *
     * @return 成功时为结果 JSON（可能是 `null` 值），失败时抛 [NativeCommandException]
     */
    @Throws(NativeCommandException::class)
    fun invoke(command: String, payload: JSONObject? = null): Any? {
        if (!initialized) throw NativeCommandException("运行时尚未初始化")
        val raw = nativeInvoke(command, (payload ?: JSONObject()).toString())
        val parsed = runCatching { JSONObject(raw) }.getOrElse {
            throw NativeCommandException("native 返回了无法解析的结果: $raw")
        }
        if (!parsed.optBoolean("ok", false)) {
            throw NativeCommandException(parsed.optString("error", "未知错误"))
        }
        return parsed.opt("data")
    }

    /**
     * 交接 VpnService 建立好的 TUN 描述符。
     *
     * 传入的必须是 `ParcelFileDescriptor.detachFd()` 的结果——所有权转移给 Rust，
     * **Kotlin 之后不要再 close 它**，重复 close 会关掉一个可能已被复用的 fd 号。
     */
    fun setVpnFd(fd: Int) {
        nativeSetVpnFd(fd)
    }

    fun shutdown() {
        if (!initialized) return
        nativeShutdown()
    }

    /** 由 Rust 通过 JNI 回调，签名不可更改（见 crates/mobile/src/session.rs）。 */
    @Suppress("unused")
    private fun onNativeEvent(event: String, dataJson: String) {
        val data = runCatching { JSONObject(dataJson) }.getOrElse { JSONObject() }
        runCatching { listener?.onEvent(event, data) }
            .onFailure { Log.e(TAG, "事件处理抛出异常: $event", it) }
    }

    private external fun nativeInit(logDir: String, dataDir: String): Boolean
    private external fun nativeConnectSignal(url: String)
    private external fun nativeInvoke(command: String, payloadJson: String): String
    private external fun nativeSetVpnFd(fd: Int)
    private external fun nativeShutdown()
}

class NativeCommandException(message: String) : Exception(message)
