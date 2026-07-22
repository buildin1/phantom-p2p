package com.buildin1.phantom_p2p.data

interface TunnelStreamBridge {
    fun isReady(): Boolean
    fun openTcpStream(targetPort: Int, listener: TcpStreamListener): TcpStreamHandle?
    fun setInboundTcpStreamListener(listener: InboundTcpStreamListener?) {}
}

interface TcpStreamHandle {
    fun write(data: ByteArray)
    fun close()
}

interface TcpStreamListener {
    fun onData(data: ByteArray)
    fun onClosed()
    fun onError(message: String)
}

interface InboundTcpStreamListener {
    fun onInboundTcpStream(targetPort: Int, handle: TcpStreamHandle): TcpStreamListener?
}

class PendingQuicStreamBridge : TunnelStreamBridge {
    override fun isReady(): Boolean = false
    override fun openTcpStream(targetPort: Int, listener: TcpStreamListener): TcpStreamHandle? = null
}