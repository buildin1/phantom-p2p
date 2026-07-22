package com.buildin1.phantom_p2p.data

import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class TcpVpnEngine(
    private val bridge: TunnelStreamBridge,
    private val writePacket: (ByteArray) -> Unit,
    private val onBytesTx: (Int) -> Unit,
    private val onBytesRx: (Int) -> Unit,
    private val onLog: (String) -> Unit
) {
    private val flows = ConcurrentHashMap<TcpFlowKey, TcpFlowState>()
    private val writeLock = Any()
    private val retransmitExecutor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "phantom-tcp-retransmit").apply { isDaemon = true }
    }

    init {
        retransmitExecutor.scheduleAtFixedRate(
            { retransmitExpiredSegments() },
            RETRANSMIT_INTERVAL_MS,
            RETRANSMIT_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        )
    }

    fun handlePacket(rawPacket: ByteArray, length: Int): Boolean {
        val packet = IpTcpPacket.parse(rawPacket, length) ?: return false
        onBytesTx(length)

        if (!bridge.isReady()) {
            reject(packet)
            return true
        }

        if (packet.isRst || packet.isFin) {
            flows.remove(packet.key())?.handle?.close()
            acknowledgeClose(packet)
            return true
        }

        if (packet.isSyn && !packet.isAck) {
            val key = packet.key()
            val stream = bridge.openTcpStream(packet.destinationPort, FlowListener(key))
            if (stream == null) {
                reject(packet)
                return true
            }
            flows[key] = TcpFlowState(
                handle = stream,
                lastPacket = packet,
                remoteSequence = (INITIAL_SEQUENCE + 1) and U32_MASK,
                appAck = IpTcpPacket.nextAck(packet),
                appSequence = IpTcpPacket.nextAck(packet)
            )
            val synAck = IpTcpPacket.buildTcpResponse(
                request = packet,
                sequenceNumber = INITIAL_SEQUENCE,
                acknowledgementNumber = IpTcpPacket.nextAck(packet),
                flags = IpTcpPacket.FLAG_SYN or IpTcpPacket.FLAG_ACK,
                tcpOptions = IpTcpPacket.mssOption(MAX_TCP_PAYLOAD)
            )
            safeWritePacket(synAck)
            return true
        }

        if (packet.payload.isNotEmpty()) {
            val state = flows[packet.key()]
            if (state == null) {
                reject(packet)
                return true
            }
            synchronized(state) {
                state.lastPacket = packet
                acknowledgeRemote(state, packet.acknowledgementNumber)
                val expectedSequence = state.appSequence
                state.appAck = IpTcpPacket.nextAck(packet)
                if (packet.sequenceNumber == expectedSequence) {
                    state.appSequence = IpTcpPacket.nextAck(packet)
                    state.handle.write(packet.payload)
                } else if (sequenceBefore(packet.sequenceNumber, expectedSequence)) {
                    state.appAck = expectedSequence
                } else {
                    state.appAck = expectedSequence
                    onLog("TCP out-of-order packet ignored seq=${packet.sequenceNumber} expected=$expectedSequence")
                }
            }
            val ack = IpTcpPacket.buildTcpResponse(
                request = packet,
                sequenceNumber = state.remoteSequence,
                acknowledgementNumber = state.appAck,
                flags = IpTcpPacket.FLAG_ACK
            )
            safeWritePacket(ack)
            return true
        }

        flows[packet.key()]?.let { state ->
            synchronized(state) {
                state.lastPacket = packet
                if (packet.isAck) {
                    acknowledgeRemote(state, packet.acknowledgementNumber)
                }
            }
        }

        return true
    }

    fun close() {
        retransmitExecutor.shutdownNow()
        flows.values.forEach { it.handle.close() }
        flows.clear()
    }

    private fun deliverFromBridge(key: TcpFlowKey, data: ByteArray) {
        if (data.isEmpty()) return
        val state = flows[key] ?: return
        var offset = 0
        while (offset < data.size) {
            val end = (offset + MAX_TCP_PAYLOAD).coerceAtMost(data.size)
            val chunk = data.copyOfRange(offset, end)
            val response = synchronized(state) {
                val packet = state.lastPacket ?: return
                val sequenceNumber = state.remoteSequence
                IpTcpPacket.buildTcpResponse(
                    request = packet,
                    sequenceNumber = sequenceNumber,
                    acknowledgementNumber = state.appAck,
                    flags = IpTcpPacket.FLAG_PSH or IpTcpPacket.FLAG_ACK,
                    payload = chunk
                ).also {
                    state.remoteSequence = (state.remoteSequence + chunk.size) and U32_MASK
                    state.pendingRemoteSegments.add(RemoteSegment(sequenceNumber, chunk.size, it))
                }
            }
            safeWritePacket(response)
            offset = end
        }
    }

    private fun closeFromBridge(key: TcpFlowKey) {
        val state = flows.remove(key) ?: return
        val packet = state.lastPacket ?: return
        val fin = IpTcpPacket.buildTcpResponse(
            request = packet,
            sequenceNumber = state.remoteSequence,
            acknowledgementNumber = state.appAck,
            flags = IpTcpPacket.FLAG_FIN or IpTcpPacket.FLAG_ACK
        )
        safeWritePacket(fin)
    }

    private fun reject(packet: IpTcpPacket) {
        val rst = IpTcpPacket.buildTcpResponse(
            request = packet,
            sequenceNumber = packet.acknowledgementNumber,
            acknowledgementNumber = IpTcpPacket.nextAck(packet),
            flags = IpTcpPacket.FLAG_RST or IpTcpPacket.FLAG_ACK
        )
        safeWritePacket(rst)
        onLog("TCP 数据面缺少 PC 兼容 QUIC bridge，已拒绝 ${packet.destinationAddress.hostAddress}:${packet.destinationPort}")
    }

    private fun acknowledgeClose(packet: IpTcpPacket) {
        val ack = IpTcpPacket.buildTcpResponse(
            request = packet,
            sequenceNumber = packet.acknowledgementNumber,
            acknowledgementNumber = IpTcpPacket.nextAck(packet),
            flags = IpTcpPacket.FLAG_ACK
        )
        safeWritePacket(ack)
    }

    private fun safeWritePacket(packet: ByteArray) {
        runCatching {
            synchronized(writeLock) {
                writePacket(packet)
            }
        }.onSuccess {
            onBytesRx(packet.size)
        }.onFailure {
            onLog("TCP TUN write failed: ${it.message}")
        }
    }

    private fun acknowledgeRemote(state: TcpFlowState, acknowledgementNumber: Long) {
        if (sequenceAfter(acknowledgementNumber, state.remoteAck)) {
            state.remoteAck = acknowledgementNumber
            state.duplicateRemoteAckCount = 0
            state.pendingRemoteSegments.removeAll { segment ->
                sequenceBeforeOrEqual(segment.endSequence, acknowledgementNumber)
            }
            return
        }

        if (acknowledgementNumber == state.remoteAck && state.pendingRemoteSegments.isNotEmpty()) {
            state.duplicateRemoteAckCount += 1
            if (state.duplicateRemoteAckCount >= DUP_ACK_RETRANSMIT_THRESHOLD) {
                retransmitFirstPendingLocked(state, force = true)
                state.duplicateRemoteAckCount = 0
            }
        }
    }

    private fun retransmitExpiredSegments() {
        flows.values.forEach { state ->
            synchronized(state) {
                retransmitFirstPendingLocked(state, force = false)
            }
        }
    }

    private fun retransmitFirstPendingLocked(state: TcpFlowState, force: Boolean) {
        val segment = state.pendingRemoteSegments.firstOrNull() ?: return
        val now = System.currentTimeMillis()
        if (!force && now - segment.lastSentAtMs < REMOTE_SEGMENT_RTO_MS) return
        segment.lastSentAtMs = now
        segment.retransmitCount += 1
        if (segment.retransmitCount == 1 || segment.retransmitCount == 3 || segment.retransmitCount % 10 == 0) {
            onLog("TCP retransmit seq=${segment.sequenceNumber} len=${segment.payloadLength} retry=${segment.retransmitCount}")
        }
        safeWritePacket(segment.packet)
    }

    private fun sequenceBefore(left: Long, right: Long): Boolean =
        ((left - right) and U32_MASK) > 0x7FFF_FFFFL

    private fun sequenceAfter(left: Long, right: Long): Boolean = sequenceBefore(right, left)

    private fun sequenceBeforeOrEqual(left: Long, right: Long): Boolean = left == right || sequenceBefore(left, right)

    companion object {
        private const val INITIAL_SEQUENCE = 0x50485032L
        private const val U32_MASK = 0xFFFF_FFFFL
        private const val MAX_TCP_PAYLOAD = 1200
        private const val RETRANSMIT_INTERVAL_MS = 500L
        private const val REMOTE_SEGMENT_RTO_MS = 1000L
        private const val DUP_ACK_RETRANSMIT_THRESHOLD = 3
        private const val HOST_TUN_IP = "10.219.0.1"
        private const val GUEST_TUN_IP = "10.219.0.2"
        private val nextInboundPort = AtomicInteger(40000)

        fun forTun(
            tunOut: FileOutputStream,
            bridge: TunnelStreamBridge,
            onBytesTx: (Int) -> Unit,
            onBytesRx: (Int) -> Unit,
            onLog: (String) -> Unit
        ): TcpVpnEngine = TcpVpnEngine(
            bridge = bridge,
            writePacket = { packet ->
                tunOut.write(packet)
                tunOut.flush()
            },
            onBytesTx = onBytesTx,
            onBytesRx = onBytesRx,
            onLog = onLog
        ).also { bridge.setInboundTcpStreamListener(it.InboundListener()) }
    }

    private inner class FlowListener(private val key: TcpFlowKey) : TcpStreamListener {
        override fun onData(data: ByteArray) {
            deliverFromBridge(key, data)
        }

        override fun onClosed() {
            closeFromBridge(key)
        }

        override fun onError(message: String) {
            onLog("TCP bridge stream error: $message")
            closeFromBridge(key)
        }
    }

    private data class TcpFlowState(
        val handle: TcpStreamHandle,
        var lastPacket: IpTcpPacket?,
        var remoteSequence: Long,
        var appAck: Long,
        var appSequence: Long,
        var remoteAck: Long = 0,
        var duplicateRemoteAckCount: Int = 0,
        val pendingRemoteSegments: MutableList<RemoteSegment> = mutableListOf()
    )

    private data class RemoteSegment(
        val sequenceNumber: Long,
        val payloadLength: Int,
        val packet: ByteArray,
        var lastSentAtMs: Long = System.currentTimeMillis(),
        var retransmitCount: Int = 0
    ) {
        val endSequence: Long get() = (sequenceNumber + payloadLength) and U32_MASK
    }

    private inner class InboundListener : InboundTcpStreamListener {
        override fun onInboundTcpStream(targetPort: Int, handle: TcpStreamHandle): TcpStreamListener? {
            val localPort = nextInboundPort.getAndIncrement()
            val key = TcpFlowKey(
                sourceAddress = GUEST_TUN_IP,
                sourcePort = localPort,
                destinationAddress = HOST_TUN_IP,
                destinationPort = targetPort
            )
            val request = IpTcpPacket.synthetic(
                sourceAddress = InetAddress.getByName(GUEST_TUN_IP),
                destinationAddress = InetAddress.getByName(HOST_TUN_IP),
                sourcePort = localPort,
                destinationPort = targetPort,
                sequenceNumber = INITIAL_SEQUENCE,
                acknowledgementNumber = 0,
                flags = IpTcpPacket.FLAG_SYN
            )
            flows[key] = TcpFlowState(
                handle = handle,
                lastPacket = request,
                remoteSequence = INITIAL_SEQUENCE + 1,
                appAck = INITIAL_SEQUENCE + 1,
                appSequence = INITIAL_SEQUENCE + 1
            )
            val syn = request.toPacket()
            safeWritePacket(syn)
            return FlowListener(key)
        }
    }
}