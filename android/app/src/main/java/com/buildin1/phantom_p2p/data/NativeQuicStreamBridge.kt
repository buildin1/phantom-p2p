package com.buildin1.phantom_p2p.data

import android.net.VpnService
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class NativeQuicStreamBridge private constructor(
    private val service: VpnService,
    private val mode: String,
    private val endpoint: String,
    private val relayToken: String,
    private val localPort: Int,
    private val isGuest: Boolean,
    private val onLog: (String) -> Unit
) : TunnelStreamBridge {
    private val streams = ConcurrentHashMap<Long, NativeTcpStreamHandle>()
    private val inboundStreams = ConcurrentHashMap<Long, NativeTcpStreamHandle>()
    @Volatile
    private var inboundListener: InboundTcpStreamListener? = null
    @Volatile
    private var nativeHandle: Long = 0L

    init {
        if (NativeQuicLibrary.isLoaded) {
            nativeHandle = runCatching {
                nativeCreateBridge(mode, endpoint, relayToken, localPort, isGuest)
            }.onFailure {
                onLog("native QUIC bridge 初始化失败: ${it.message}")
            }.getOrDefault(0L)
        }
    }

    override fun isReady(): Boolean = NativeQuicLibrary.isLoaded && nativeHandle != 0L

    override fun openTcpStream(targetPort: Int, listener: TcpStreamListener): TcpStreamHandle? {
        if (!isReady()) return null
        val streamId = runCatching {
            nativeOpenTcpStream(nativeHandle, targetPort)
        }.onFailure {
            listener.onError(it.message ?: "native open stream failed")
        }.getOrDefault(0L)
        if (streamId == 0L) return null

        val handle = NativeTcpStreamHandle(streamId, listener)
        streams[streamId] = handle
        return handle
    }

    override fun setInboundTcpStreamListener(listener: InboundTcpStreamListener?) {
        inboundListener = listener
    }

    fun close() {
        streams.values.forEach { it.close() }
        inboundStreams.values.forEach { it.close() }
        streams.clear()
        inboundStreams.clear()
        val handle = nativeHandle
        nativeHandle = 0L
        if (NativeQuicLibrary.isLoaded && handle != 0L) {
            runCatching { nativeCloseBridge(handle) }
        }
    }

    private inner class NativeTcpStreamHandle(
        private val streamId: Long,
        var listener: TcpStreamListener
    ) : TcpStreamHandle {
        @Volatile
        private var closed = false

        override fun write(data: ByteArray) {
            if (closed) return
            if (!NativeQuicLibrary.isLoaded || nativeHandle == 0L) {
                listener.onError("native QUIC bridge is not loaded")
                close()
                return
            }
            runCatching {
                nativeWriteTcpStream(nativeHandle, streamId, data)
            }.onFailure {
                listener.onError(it.message ?: "native write failed")
                close()
            }
        }

        override fun close() {
            if (closed) return
            closed = true
            streams.remove(streamId)
            inboundStreams.remove(streamId)
            if (NativeQuicLibrary.isLoaded && nativeHandle != 0L) {
                runCatching { nativeCloseTcpStream(nativeHandle, streamId) }
            }
        }
    }

    @Suppress("unused")
    private fun onNativeTcpData(streamId: Long, data: ByteArray) {
        runCatching {
            streams[streamId]?.listener?.onData(data) ?: inboundStreams[streamId]?.listener?.onData(data)
        }.onFailure {
            onLog("native TCP data callback failed: ${it.message}")
        }
    }

    @Suppress("unused")
    private fun onNativeTcpClosed(streamId: Long) {
        runCatching {
            streams.remove(streamId)?.listener?.onClosed() ?: inboundStreams.remove(streamId)?.listener?.onClosed()
        }.onFailure {
            onLog("native TCP close callback failed: ${it.message}")
        }
    }

    @Suppress("unused")
    private fun onNativeInboundTcpStream(streamId: Long, targetPort: Int) {
        runCatching {
            val listener = InboundTcpStreamListenerAdapter()
            val handle = NativeTcpStreamHandle(streamId, listener)
            inboundStreams[streamId] = handle
            inboundListener?.onInboundTcpStream(targetPort, handle)?.let { handle.listener = it }
        }.onFailure {
            inboundStreams.remove(streamId)
            onLog("native inbound TCP callback failed: ${it.message}")
        }
    }

    private inner class InboundTcpStreamListenerAdapter : TcpStreamListener {
        override fun onData(data: ByteArray) = Unit
        override fun onClosed() = Unit
        override fun onError(message: String) = onLog(message)
    }

    @Suppress("unused")
    private fun onProtectSocket(fd: Int): Boolean = service.protect(fd)

    private external fun nativeCreateBridge(mode: String, endpoint: String, relayToken: String, localPort: Int, isGuest: Boolean): Long
    private external fun nativeOpenTcpStream(handle: Long, targetPort: Int): Long
    private external fun nativeWriteTcpStream(handle: Long, streamId: Long, data: ByteArray)
    private external fun nativeCloseTcpStream(handle: Long, streamId: Long)
    private external fun nativeCloseBridge(handle: Long)

    companion object {
        fun createOrPending(
            service: VpnService,
            mode: String,
            endpoint: String,
            relayToken: String,
            localPort: Int,
            isGuest: Boolean,
            onLog: (String) -> Unit
        ): TunnelStreamBridge {
            if (!NativeQuicLibrary.isLoaded) {
                onLog("native QUIC bridge 尚未打包，TCP 数据面保持拒绝模式")
                return PendingQuicStreamBridge()
            }
            return NativeQuicStreamBridge(service, mode, endpoint, relayToken, localPort, isGuest, onLog).also {
                if (!it.isReady()) onLog("native QUIC bridge 未就绪，TCP 数据面保持拒绝模式")
            }
        }
    }
}

private object NativeQuicLibrary {
    val isLoaded: Boolean = runCatching {
        System.loadLibrary("phantom_mobile")
    }.isSuccess
}