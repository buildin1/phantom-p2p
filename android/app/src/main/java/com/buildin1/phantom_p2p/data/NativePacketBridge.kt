package com.buildin1.phantom_p2p.data

import android.content.Context
import com.buildin1.phantom_p2p.PhantomVpnService

class NativePacketBridge private constructor(
    private val handle: Long,
    private val onPacket: (ByteArray) -> Unit,
    private val onLog: (String) -> Unit
) {
    fun writePacket(packet: ByteArray) = nativeWritePacket(handle, packet)
    fun close() {
        nativeCloseBridge(handle)
        service = null
    }

    fun isReady() = handle != 0L

    fun onNativeIpPacket(packet: ByteArray) = onPacket(packet)

    /** Called from Rust before the QUIC socket is used by the VPN data plane. */
    fun onProtectSocket(fd: Int): Boolean {
        return runCatching { NativePacketBridge.service?.protect(fd) ?: false }
            .onFailure { onLog("protect VPN socket failed: ${it.message}") }
            .getOrDefault(false)
    }

    private external fun nativeWritePacket(handle: Long, packet: ByteArray)
    private external fun nativeCloseBridge(handle: Long)
    private external fun nativeCreateBridge(mode: String, endpoint: String, relayToken: String, localPort: Int, isGuest: Boolean): Long
    private external fun nativeStartPacketStream(handle: Long): Boolean

    companion object {
        @Volatile
        private var service: PhantomVpnService? = null

        init { runCatching { System.loadLibrary("phantom_mobile") } }

        fun create(
            context: Context,
            mode: String,
            endpoint: String,
            relayToken: String,
            localPort: Int,
            isGuest: Boolean,
            onPacket: (ByteArray) -> Unit,
            onLog: (String) -> Unit
        ): NativePacketBridge? {
            service = context as? PhantomVpnService
            val bridge = NativePacketBridge(0L, onPacket, onLog)
            val handle = runCatching {
                bridge.nativeCreateBridge(mode, endpoint, relayToken, localPort, isGuest)
            }.getOrElse {
                onLog("native packet bridge 初始化失败: ${it.message}")
                return null
            }
            if (handle == 0L) return null
            val result = NativePacketBridge(handle, onPacket, onLog)
            if (!result.nativeStartPacketStream(handle)) {
                result.nativeCloseBridge(handle)
                return null
            }
            return result
        }

    }
}
