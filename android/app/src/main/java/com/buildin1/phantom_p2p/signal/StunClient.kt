package com.buildin1.phantom_p2p.signal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * STUN RFC-5389 / RFC-5780 客户端，支持双 socket 检测和 CHANGE_REQUEST 过滤行为探测。
 * 与 PC 端 crates/core/src/stun.rs 和 nat.rs 行为完全对齐：
 * - 双 socket 端点无关映射 (EIM) 检测
 * - CHANGE_REQUEST 过滤行为探测 (EndpointIndependent / AddressDependent / AddressPortDependent)
 * - 对称型 NAT 端口模式分析 (递增 / 随机，对应 PC classify_symmetric_pattern)
 */
class StunClient(
    private val logger: ((String) -> Unit)? = null
) {

    data class StunProbe(
        val server: String,
        val externalIp: String,
        val externalPort: Int,
        val rttMs: Long
    )

    data class NatDetectionResult(
        val natType: String,
        val mappingBehavior: String,
        val filteringBehavior: String,
        val portPattern: String,
        val confidence: String,
        val externalIp: String,
        val externalPort: Int,
        val networkPriority: String,
        val probes: List<StunProbe>
    )

    enum class FilteringBehavior {
        EndpointIndependent, AddressDependent, AddressPortDependent, Unknown;
        fun displayName() = when (this) {
            EndpointIndependent  -> "EIF (端点无关过滤)"
            AddressDependent     -> "ADF (地址相关过滤)"
            AddressPortDependent -> "APDF (地址+端口相关过滤)"
            Unknown              -> "未知"
        }
    }

    private data class QueryResult(
        val externalIp: String,
        val externalPort: Int,
        val rttMs: Long,
        val responderAddr: InetSocketAddress?,
        val otherAddress: InetSocketAddress?,
        val changedAddress: InetSocketAddress?
    )

    private val stunServers = listOf(
        "stun.dcalling.de"     to 3478,
        "stun.skydrone.aero"   to 3478,
        "stun.nextcloud.com"   to 443
    )

    /** IceEngine 用：用已有 socket 探测所有 STUN 服务器，返回外部映射列表 */
    fun queryAll(socket: DatagramSocket): List<StunProbe> {
        return stunServers.mapNotNull { (host, port) ->
            runCatching {
                val addr = InetSocketAddress(InetAddress.getByName(host), port)
                queryWithOptions(socket, addr, changeIp = false, changePort = false)
                    ?.let { r -> StunProbe("$host:$port", r.externalIp, r.externalPort, r.rttMs) }
            }.onFailure { logger?.invoke("⚠️ STUN 节点不可达: $host:$port (${it.message})") }
             .getOrNull()
        }
    }

    /**
     * 完整 NAT 检测，对应 PC 端 detect_nat_type():
     * Phase 1 — Socket A 探测所有 STUN 服务器
     * Phase 2 — Socket B (不同源端口) 再次探测
     * Phase 3 — CHANGE_REQUEST 过滤行为探测
     * 依据 nat.rs analyze_multi_round() 算法分类
     */
    suspend fun detectNat(): NatDetectionResult = withContext(Dispatchers.IO) {
        val probesA = mutableListOf<StunProbe>()
        val probesB = mutableListOf<StunProbe>()

        // ── Socket A ──────────────────────────────────────────────────
        logger?.invoke("双 socket 探测: Socket A…")
        try {
            val sockA = DatagramSocket()
            sockA.soTimeout = STUN_TIMEOUT_MS
            try {
                for ((host, port) in stunServers) {
                    runCatching {
                        val addr = InetSocketAddress(InetAddress.getByName(host), port)
                        queryWithOptions(sockA, addr, false, false)
                    }.getOrNull()?.let { r ->
                        probesA += StunProbe("$host:$port", r.externalIp, r.externalPort, r.rttMs)
                        logger?.invoke("Socket A: $host → ${r.externalIp}:${r.externalPort} (${r.rttMs}ms)")
                    } ?: logger?.invoke("⚠️ Socket A: $host:$port 无响应")
                }
            } finally { sockA.close() }
        } catch (e: Exception) { logger?.invoke("Socket A 异常: ${e.message}") }

        // ── Socket B ──────────────────────────────────────────────────
        logger?.invoke("双 socket 探测: Socket B…")
        try {
            val sockB = DatagramSocket()
            sockB.soTimeout = STUN_TIMEOUT_MS
            try {
                for ((host, port) in stunServers) {
                    runCatching {
                        val addr = InetSocketAddress(InetAddress.getByName(host), port)
                        queryWithOptions(sockB, addr, false, false)
                    }.getOrNull()?.let { r ->
                        probesB += StunProbe("$host:$port [B]", r.externalIp, r.externalPort, r.rttMs)
                    } ?: logger?.invoke("⚠️ Socket B: $host:$port 无响应")
                }
            } finally { sockB.close() }
        } catch (e: Exception) { logger?.invoke("Socket B 异常: ${e.message}") }

        val allProbes = probesA + probesB
        if (allProbes.isEmpty()) {
            return@withContext NatDetectionResult(
                natType = "UDP 不通", mappingBehavior = "--", filteringBehavior = "--",
                portPattern = "--", confidence = "低", externalIp = "", externalPort = 0,
                networkPriority = "--", probes = emptyList()
            )
        }

        // ── CHANGE_REQUEST 过滤行为探测 ──────────────────────────────
        logger?.invoke("过滤行为探测 (CHANGE_REQUEST)…")
        val (filterBehavior, filterDetail) = detectFilteringBehavior()
        logger?.invoke("过滤行为: ${filterBehavior.displayName()} — $filterDetail")

        // ── EIM 分析 (端点无关映射，对应 RFC 5780 Section 4.4) ──
        // 正确测试方式：同一个 socket 向多个 STUN 服务器查询，外部端口全部相同 = EIM
        // crossSamePort / crossDiff 检测的是"不同本地端口是否得到相同外部端口"，
        // 这与 EIM 定义无关，会错误地把普通 Cone NAT 判成 Symmetric，故移除。
        val portsA = probesA.map { it.externalPort }
        val portsB = probesB.map { it.externalPort }
        val eimA = portsA.size >= 2 && portsA.all { it == portsA[0] }
        val eimB = portsB.size >= 2 && portsB.all { it == portsB[0] }
        // 只要任意一个 socket 独立确认了 EIM，就视为 EIM（优先使用 socket A）
        val eim = when {
            portsA.size >= 2 && portsB.size >= 2 -> eimA || eimB
            portsA.size >= 2 -> eimA
            portsB.size >= 2 -> eimB
            else             -> false  // 样本不足，无法判断，保守地归入 Symmetric
        }

        val firstIp   = probesA.firstOrNull()?.externalIp   ?: probesB.firstOrNull()?.externalIp   ?: ""
        val firstPort = probesA.firstOrNull()?.externalPort ?: probesB.firstOrNull()?.externalPort ?: 0
        val avgRtt    = allProbes.map { it.rttMs }.average().toLong().coerceAtLeast(0)
        val networkPriority = when {
            avgRtt < 50  -> "优秀 (${avgRtt}ms)"
            avgRtt < 100 -> "良好 (${avgRtt}ms)"
            avgRtt < 200 -> "一般 (${avgRtt}ms)"
            else         -> "较差 (${avgRtt}ms)"
        }
        val allPortsSample = (portsA + portsB).filter { it > 0 }

        if (eim) {
            // Cone NAT — 用过滤行为细分 (对应 PC nat.rs classify_filtering)
            val natType = when (filterBehavior) {
                FilteringBehavior.EndpointIndependent  -> "Full Cone NAT (NAT1)"
                FilteringBehavior.AddressDependent     -> "Address Restricted Cone (NAT2)"
                FilteringBehavior.AddressPortDependent -> "Port Restricted Cone (NAT3)"
                FilteringBehavior.Unknown              -> "Cone NAT (NAT1~3, 过滤行为未知)"
            }
            NatDetectionResult(
                natType = natType,
                mappingBehavior = "EIM (端点无关映射, 外部端口 ${formatPortBrief(allPortsSample)})",
                filteringBehavior = "${filterBehavior.displayName()} — $filterDetail",
                portPattern = "固定端口",
                confidence = if (filterBehavior != FilteringBehavior.Unknown) "高" else "中",
                externalIp = firstIp, externalPort = firstPort,
                networkPriority = networkPriority, probes = allProbes
            )
        } else {
            // Symmetric NAT — 分析端口递增/随机模式 (对应 PC classify_symmetric_pattern)
            val (symNatType, portPattern) = classifySymmetric(allPortsSample)
            NatDetectionResult(
                natType = symNatType,
                mappingBehavior = "APDM/ADM (端口随目标变化, 样本: ${formatPortBrief(allPortsSample)})",
                filteringBehavior = "对称映射，过滤行为不单独区分",
                portPattern = portPattern,
                confidence = if (allPortsSample.size >= 4) "高" else "中",
                externalIp = firstIp, externalPort = firstPort,
                networkPriority = networkPriority, probes = allProbes
            )
        }
    }

    // ── CHANGE_REQUEST 过滤行为探测 ─────────────────────────────────────────

    private fun detectFilteringBehavior(): Pair<FilteringBehavior, String> {
        for ((host, port) in stunServers) {
            val result = tryDetectFiltering(host, port)
            if (result != null) return result
        }
        return FilteringBehavior.Unknown to "所有服务器均不支持 CHANGE_REQUEST 或无响应"
    }

    private fun tryDetectFiltering(host: String, port: Int): Pair<FilteringBehavior, String>? {
        return try {
            val sock = DatagramSocket()
            sock.soTimeout = STUN_TIMEOUT_MS
            try {
                val addr = InetSocketAddress(InetAddress.getByName(host), port)
                val baseline = queryWithOptions(sock, addr, false, false) ?: return null
                // 要求服务器从不同端口回复
                val cp  = queryWithOptions(sock, addr, changeIp = false, changePort = true)
                // 要求服务器从不同 IP+端口回复
                val cib = queryWithOptions(sock, addr, changeIp = true,  changePort = true)

                val hasAlt       = baseline.otherAddress != null || baseline.changedAddress != null
                val cpEffective  = cp  != null && cp.responderAddr  != null && cp.responderAddr  != baseline.responderAddr
                val cibEffective = cib != null && cib.responderAddr != null && cib.responderAddr != baseline.responderAddr

                if (!hasAlt && !cpEffective && !cibEffective) return null  // 服务器不支持

                val behavior = when {
                    cpEffective && cibEffective  -> FilteringBehavior.EndpointIndependent
                    cpEffective && !cibEffective -> FilteringBehavior.AddressDependent
                    !cpEffective                 -> FilteringBehavior.AddressPortDependent
                    else                         -> FilteringBehavior.Unknown
                }
                val detail = "baseline=${baseline.externalPort}, cp=${if (cpEffective) "pass" else "blocked"}, cib=${if (cibEffective) "pass" else "blocked"} ($host)"
                behavior to detail
            } finally { sock.close() }
        } catch (e: Exception) {
            logger?.invoke("过滤探测失败 $host: ${e.message}")
            null
        }
    }

    // ── 对称型 NAT 端口模式分类（对应 nat.rs classify_symmetric_pattern）──────

    private fun classifySymmetric(ports: List<Int>): Pair<String, String> {
        if (ports.size <= 1) return "Symmetric NAT (NAT4)" to "样本不足"
        val diffs = ports.zipWithNext().map { (a, b) -> b - a }
        val posSmall = diffs.count { it in 1..16 }
        val ratio = posSmall.toFloat() / diffs.size
        return if (ratio >= 0.68f) {
            val minD = diffs.filter { it > 0 }.minOrNull() ?: 1
            val maxD = diffs.filter { it > 0 }.maxOrNull() ?: 1
            "Symmetric NAT (NAT4, 递增)" to (if (minD == maxD) "递增+$minD" else "递增+$minD~$maxD")
        } else {
            "Symmetric NAT (NAT4, 随机)" to "随机/跳跃 (递增占比 ${(ratio * 100).toInt()}%)"
        }
    }

    private fun formatPortBrief(ports: List<Int>): String {
        if (ports.isEmpty()) return "--"
        val uniq = ports.toSortedSet().toList()
        return if (uniq.size <= 6) uniq.joinToString(", ")
               else "${uniq.first()}..${uniq.last()} (${uniq.size}个)"
    }

    // ── STUN 协议实现 ───────────────────────────────────────────────────────

    /**
     * 发送一次 Binding Request（可附带 CHANGE_REQUEST 属性），解析响应。
     * 捕获 responder 源地址，用于过滤行为分析。
     * 对应 PC stun.rs query_with_options()。
     */
    private fun queryWithOptions(
        socket: DatagramSocket,
        addr: InetSocketAddress,
        changeIp: Boolean,
        changePort: Boolean
    ): QueryResult? {
        val txId    = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val request = buildBindingRequest(txId, changeIp, changePort)
        val t0      = System.currentTimeMillis()
        socket.send(DatagramPacket(request, request.size, addr))

        val buf = ByteArray(1500)
        while (true) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                socket.receive(pkt)
            } catch (_: SocketTimeoutException) { return null }
            val n = pkt.length
            if (n < 20) continue

            // Binding Response (0x0101)
            val msgType = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
            if (msgType != 0x0101) continue

            // Magic Cookie
            val cookie = ((buf[4].toInt() and 0xFF).toLong() shl 24) or
                         ((buf[5].toInt() and 0xFF).toLong() shl 16) or
                         ((buf[6].toInt() and 0xFF).toLong() shl  8) or
                          (buf[7].toInt() and 0xFF).toLong()
            if (cookie != MAGIC_COOKIE) continue

            // Transaction ID
            if (!txId.contentEquals(buf.copyOfRange(8, 20))) {
                if (System.currentTimeMillis() - t0 >= STUN_TIMEOUT_MS) return null
                continue  // stale packet, keep waiting
            }

            val rtt    = System.currentTimeMillis() - t0
            val msgLen = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
            var pos    = 20
            var xorMapped: Pair<String, Int>? = null
            var mapped: Pair<String, Int>?    = null
            var otherAddress: InetSocketAddress?   = null
            var changedAddress: InetSocketAddress? = null

            while (pos + 4 <= n && pos < 20 + msgLen) {
                val attrType = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
                val attrLen  = ((buf[pos + 2].toInt() and 0xFF) shl 8) or (buf[pos + 3].toInt() and 0xFF)
                if (pos + 4 + attrLen > n) break
                val attrData = buf.copyOfRange(pos + 4, pos + 4 + attrLen)
                when (attrType) {
                    0x0020 -> xorMapped      = parseXorMapped(attrData)
                    0x0001 -> mapped         = parsePlainAddr(attrData)
                    0x0005 -> changedAddress = parsePlainAddr(attrData)?.toInetSocketAddress()  // CHANGED-ADDRESS
                    0x802c -> otherAddress   = parsePlainAddr(attrData)?.toInetSocketAddress()  // OTHER-ADDRESS
                    // 0x802b RESPONSE-ORIGIN: captured via pkt.socketAddress
                }
                val padded = (attrLen + 3) and 3.inv()
                pos += 4 + padded
            }

            val mapping = xorMapped ?: mapped ?: continue
            return QueryResult(
                externalIp    = mapping.first,
                externalPort  = mapping.second,
                rttMs         = rtt,
                responderAddr = pkt.socketAddress as? InetSocketAddress,
                otherAddress  = otherAddress,
                changedAddress = changedAddress
            )
        }
    }

    private fun Pair<String, Int>.toInetSocketAddress(): InetSocketAddress? =
        runCatching { InetSocketAddress(InetAddress.getByName(first), second) }.getOrNull()

    private fun parseXorMapped(attr: ByteArray): Pair<String, Int>? {
        if (attr.size < 8 || attr[1] != 0x01.toByte()) return null   // IPv4 only
        val xPort = ((attr[2].toInt() and 0xFF) shl 8) or (attr[3].toInt() and 0xFF)
        val port  = xPort xor ((MAGIC_COOKIE ushr 16).toInt() and 0xFFFF)
        val xIp   = ((attr[4].toInt() and 0xFF).toLong() shl 24) or
                    ((attr[5].toInt() and 0xFF).toLong() shl 16) or
                    ((attr[6].toInt() and 0xFF).toLong() shl  8) or
                     (attr[7].toInt() and 0xFF).toLong()
        val ipInt = xIp xor MAGIC_COOKIE
        val ip = "${(ipInt ushr 24) and 0xFF}.${(ipInt ushr 16) and 0xFF}" +
                 ".${(ipInt ushr 8) and 0xFF}.${ipInt and 0xFF}"
        return ip to port
    }

    private fun parsePlainAddr(attr: ByteArray): Pair<String, Int>? {
        if (attr.size < 8 || attr[1] != 0x01.toByte()) return null   // IPv4 only
        val port = ((attr[2].toInt() and 0xFF) shl 8) or (attr[3].toInt() and 0xFF)
        val ip   = "${attr[4].toInt() and 0xFF}.${attr[5].toInt() and 0xFF}" +
                   ".${attr[6].toInt() and 0xFF}.${attr[7].toInt() and 0xFF}"
        return ip to port
    }

    private fun buildBindingRequest(txId: ByteArray, changeIp: Boolean, changePort: Boolean): ByteArray {
        var changeFlag = 0
        if (changeIp)   changeFlag = changeFlag or 0x04
        if (changePort) changeFlag = changeFlag or 0x02
        val attrBytes = if (changeFlag != 0) 8 else 0   // 4B type+len + 4B value
        val buf = ByteBuffer.allocate(20 + attrBytes)
        buf.putShort(0x0001)                 // Binding Request
        buf.putShort(attrBytes.toShort())    // Message length
        buf.putInt(MAGIC_COOKIE.toInt())     // Magic Cookie
        buf.put(txId)                        // Transaction ID (12 bytes)
        if (changeFlag != 0) {
            buf.putShort(0x0003)             // ATTR_CHANGE_REQUEST
            buf.putShort(4)                  // Attribute length = 4
            buf.putInt(changeFlag)           // Change flags (bit1=change_port, bit2=change_ip)
        }
        return buf.array()
    }

    companion object {
        private const val MAGIC_COOKIE    = 0x2112A442L
        private const val STUN_TIMEOUT_MS = 3000
    }
}
