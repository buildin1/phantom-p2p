package com.buildin1.phantom_p2p.data

import android.content.Context

class NativePacketBridge private constructor(
    private val handle: Long,
    private val onPacket: (ByteArray) -> Unit,
    private val onLog: (String) -> Unit
) {
    fun writePacket(packet: ByteArray) = nativeWritePacket(handle, packet)
    fun close() = nativeCloseBridge(handle)

    fun isReady() = handle != 0L

    fun onNativeIpPacket(packet: ByteArray) = onPacket(packet)

    private external fun nativeWritePacket(handle: Long, packet: ByteArray)
    private external fun nativeCloseBridge(handle: Long)
    private external fun nativeCreateBridge(mode: String, endpoint: String, relayToken: String, localPort: Int, isGuest: Boolean): Long
    private external fun nativeStartPacketStream(handle: Long): Boolean

    companion object {
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
