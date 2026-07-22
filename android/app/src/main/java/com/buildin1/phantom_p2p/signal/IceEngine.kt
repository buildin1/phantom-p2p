package com.buildin1.phantom_p2p.signal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import kotlin.math.min

class IceEngine(
    private val stunClient: StunClient = StunClient()
) {

    data class LocalIceSession(
        val socket: DatagramSocket,
        val candidates: List<IceCandidate>,
        val ufrag: String,
        val pwd: String,
        val natType: String
    )

    data class PunchResult(
        val success: Boolean,
        val peerAddress: InetSocketAddress?,
        val latencyMs: Int,
        val reason: String
    )

    suspend fun gatherCandidates(existingSocket: DatagramSocket? = null): LocalIceSession = withContext(Dispatchers.IO) {
        val socket = existingSocket ?: DatagramSocket().apply {
            reuseAddress = true
            soTimeout = 4000
        }

        val candidates = mutableListOf<IceCandidate>()
        val localPort = socket.localPort

        localIpv4s().forEachIndexed { index, ip ->
            candidates += IceCandidate(
                ip = ip,
                port = localPort,
                ctype = CTYPE_HOST,
                priority = 2_130_706_175L - index,
                foundation = "h$index"
            )
        }

        val mappings = stunClient.queryAll(socket)
        mappings.forEachIndexed { index, mapping ->
            candidates += IceCandidate(
                ip = mapping.externalIp,
                port = mapping.externalPort,
                ctype = CTYPE_SERVER_REFLEXIVE,
                priority = 1_694_498_815L - index,
                foundation = "s$index"
            )
        }

        val unique = LinkedHashMap<String, IceCandidate>()
        candidates.forEach { candidate ->
            unique.putIfAbsent("${candidate.ip}:${candidate.port}", candidate)
        }

        LocalIceSession(
            socket = socket,
            candidates = unique.values.toList(),
            ufrag = generateToken(8),
            pwd = generateToken(24),
            natType = inferNatType(mappings)
        )
    }

    suspend fun runConnectivityChecks(
        socket: DatagramSocket,
        peerCandidates: List<IceCandidate>,
        startAtMs: Long
    ): PunchResult = withContext(Dispatchers.IO) {
        val initialTargets = LinkedHashMap<String, InetSocketAddress>()
        peerCandidates.forEach { candidate ->
            runCatching {
                InetSocketAddress(InetAddress.getByName(candidate.ip), candidate.port)
            }.getOrNull()?.let { address ->
                initialTargets.putIfAbsent(address.toString(), address)
            }
        }

        if (initialTargets.isEmpty()) {
            return@withContext PunchResult(false, null, 0, "无可用对端 ICE 候选")
        }

        val targets = initialTargets.values.toMutableList()
        val known = targets.mapTo(LinkedHashSet()) { it.toString() }
        val oldTimeout = socket.soTimeout
        socket.soTimeout = 20

        try {
            val now = System.currentTimeMillis()
            if (startAtMs > now) {
                kotlinx.coroutines.delay((startAtMs - now).coerceAtMost(2000))
            }

            val startedAt = System.currentTimeMillis()
            var lastSendAt = 0L
            var firstSuccess: Pair<InetSocketAddress, Int>? = null
            val receiveBuffer = ByteArray(256)

            while (System.currentTimeMillis() - startedAt < ICE_TIMEOUT_MS) {
                val current = System.currentTimeMillis()
                if (current - lastSendAt >= ICE_SEND_INTERVAL_MS) {
                    val elapsed = (current - startedAt).toInt()
                    val packetData = buildPunchPacket(elapsed)
                    targets.forEach { target ->
                        runCatching {
                            socket.send(DatagramPacket(packetData, packetData.size, target))
                        }
                    }
                    lastSendAt = current
                }

                try {
                    val packet = DatagramPacket(receiveBuffer, receiveBuffer.size)
                    socket.receive(packet)
                    if (!isPunchPacket(packet.data, packet.length)) {
                        continue
                    }

                    val from = packet.socketAddress as? InetSocketAddress ?: continue
                    if (known.add(from.toString())) {
                        targets += from
                    }

                    val elapsed = min((System.currentTimeMillis() - startedAt).toInt(), 500)
                    val ack = buildPunchPacket(elapsed)
                    runCatching {
                        socket.send(DatagramPacket(ack, ack.size, from))
                    }

                    if (firstSuccess == null) {
                        firstSuccess = from to elapsed
                    }
                } catch (_: SocketTimeoutException) {
                    // poll again
                }

                firstSuccess?.let { (address, latencyMs) ->
                    if (System.currentTimeMillis() - startedAt >= latencyMs + ICE_CONFIRM_WINDOW_MS) {
                        return@withContext PunchResult(true, address, latencyMs, "")
                    }
                }
            }

            PunchResult(false, null, 0, "ICE 连通性检测超时（已尝试 ${targets.size} 个候选）")
        } finally {
            socket.soTimeout = oldTimeout
        }
    }

    fun close(session: LocalIceSession?) {
        session?.socket?.close()
    }

    private fun localIpv4s(): List<String> {
        val result = linkedSetOf<String>()
        listOf("1.1.1.1", "8.8.8.8", "223.5.5.5").forEach { target ->
            runCatching {
                DatagramSocket().use { probe ->
                    probe.connect(InetAddress.getByName(target), 80)
                    val localIp = probe.localAddress?.hostAddress.orEmpty()
                    if (localIp.isNotBlank() && localIp != "0.0.0.0" && !localIp.startsWith("127.")) {
                        result += localIp
                    }
                }
            }
        }
        return if (result.isEmpty()) listOf("127.0.0.1") else result.toList()
    }

    private fun inferNatType(mappings: List<StunClient.StunProbe>): String {
        if (mappings.isEmpty()) return "unknown"
        val first = mappings.first()
        val allSameEndpoint = mappings.all { it.externalIp == first.externalIp && it.externalPort == first.externalPort }
        return if (allSameEndpoint) {
            "port_restricted_cone"
        } else {
            "symmetric_random"
        }
    }

    private fun generateToken(length: Int): String {
        val alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val random = SecureRandom()
        return buildString(length) {
            repeat(length) {
                append(alphabet[random.nextInt(alphabet.length)])
            }
        }
    }

    private fun buildPunchPacket(elapsedMs: Int): ByteArray {
        val packet = ByteArray(8)
        PUNCH_MAGIC.copyInto(packet, 0)
        packet[4] = ((elapsedMs shr 24) and 0xFF).toByte()
        packet[5] = ((elapsedMs shr 16) and 0xFF).toByte()
        packet[6] = ((elapsedMs shr 8) and 0xFF).toByte()
        packet[7] = (elapsedMs and 0xFF).toByte()
        return packet
    }

    private fun isPunchPacket(data: ByteArray, length: Int): Boolean {
        if (length < 8) return false
        return data[0] == PUNCH_MAGIC[0] &&
            data[1] == PUNCH_MAGIC[1] &&
            data[2] == PUNCH_MAGIC[2] &&
            data[3] == PUNCH_MAGIC[3]
    }

    companion object {
        private const val ICE_SEND_INTERVAL_MS = 15L
        private const val ICE_TIMEOUT_MS = 12_000L
        private const val ICE_CONFIRM_WINDOW_MS = 220L
        private const val CTYPE_HOST = "host"
        private const val CTYPE_SERVER_REFLEXIVE = "server_reflexive"
        private val PUNCH_MAGIC = byteArrayOf('P'.code.toByte(), 'P'.code.toByte(), '6'.code.toByte(), 'P'.code.toByte())
    }
}