package com.buildin1.phantom_p2p.data

import java.net.InetAddress

data class IpTcpPacket(
    val version: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgementNumber: Long,
    val flags: Int,
    val windowSize: Int,
    val payload: ByteArray,
    val ipHeaderLength: Int,
    val tcpHeaderLength: Int
) {
    val isSyn: Boolean get() = flags and FLAG_SYN != 0
    val isAck: Boolean get() = flags and FLAG_ACK != 0
    val isFin: Boolean get() = flags and FLAG_FIN != 0
    val isRst: Boolean get() = flags and FLAG_RST != 0

    fun key(): TcpFlowKey = TcpFlowKey(
        sourceAddress = sourceAddress.hostAddress.orEmpty(),
        sourcePort = sourcePort,
        destinationAddress = destinationAddress.hostAddress.orEmpty(),
        destinationPort = destinationPort
    )

    fun toPacket(): ByteArray {
        val ipHeaderLength = 20
        val tcpHeaderLength = 20
        val totalLength = ipHeaderLength + tcpHeaderLength + payload.size
        val out = ByteArray(totalLength)

        out[0] = 0x45
        out[1] = 0
        writeU16(out, 2, totalLength)
        writeU16(out, 4, 0)
        writeU16(out, 6, 0)
        out[8] = 64
        out[9] = 6
        sourceAddress.address.copyInto(out, 12)
        destinationAddress.address.copyInto(out, 16)
        writeU16(out, 10, checksum(out, 0, ipHeaderLength))

        val tcpOffset = ipHeaderLength
        writeU16(out, tcpOffset, sourcePort)
        writeU16(out, tcpOffset + 2, destinationPort)
        writeU32(out, tcpOffset + 4, sequenceNumber)
        writeU32(out, tcpOffset + 8, acknowledgementNumber)
        out[tcpOffset + 12] = ((tcpHeaderLength / 4) shl 4).toByte()
        out[tcpOffset + 13] = flags.toByte()
        writeU16(out, tcpOffset + 14, windowSize.coerceIn(0, 65535))
        writeU16(out, tcpOffset + 16, 0)
        writeU16(out, tcpOffset + 18, 0)
        payload.copyInto(out, tcpOffset + tcpHeaderLength)

        writeU16(out, tcpOffset + 16, tcpChecksum(out, tcpOffset, tcpHeaderLength + payload.size, sourceAddress.address, destinationAddress.address))
        return out
    }

    companion object {
        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_PSH = 0x08
        const val FLAG_ACK = 0x10

        fun parse(packet: ByteArray, length: Int): IpTcpPacket? {
            if (length < 40) return null
            val version = (packet[0].toInt() ushr 4) and 0x0F
            if (version != 4) return null
            val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
            if (ipHeaderLength < 20 || length < ipHeaderLength + 20) return null
            val protocol = packet[9].toInt() and 0xFF
            if (protocol != 6) return null
            val totalLength = readU16(packet, 2).coerceAtMost(length)
            if (totalLength < ipHeaderLength + 20) return null

            val tcpOffset = ipHeaderLength
            val tcpHeaderLength = ((packet[tcpOffset + 12].toInt() ushr 4) and 0x0F) * 4
            if (tcpHeaderLength < 20 || totalLength < tcpOffset + tcpHeaderLength) return null

            val payloadOffset = tcpOffset + tcpHeaderLength
            val payloadLength = (totalLength - payloadOffset).coerceAtLeast(0)

            return IpTcpPacket(
                version = version,
                sourceAddress = InetAddress.getByAddress(packet.copyOfRange(12, 16)),
                destinationAddress = InetAddress.getByAddress(packet.copyOfRange(16, 20)),
                sourcePort = readU16(packet, tcpOffset),
                destinationPort = readU16(packet, tcpOffset + 2),
                sequenceNumber = readU32(packet, tcpOffset + 4),
                acknowledgementNumber = readU32(packet, tcpOffset + 8),
                flags = packet[tcpOffset + 13].toInt() and 0x3F,
                windowSize = readU16(packet, tcpOffset + 14),
                payload = if (payloadLength > 0) packet.copyOfRange(payloadOffset, payloadOffset + payloadLength) else ByteArray(0),
                ipHeaderLength = ipHeaderLength,
                tcpHeaderLength = tcpHeaderLength
            )
        }

        fun buildTcpResponse(
            request: IpTcpPacket,
            sequenceNumber: Long,
            acknowledgementNumber: Long,
            flags: Int,
            payload: ByteArray = ByteArray(0),
            tcpOptions: ByteArray = ByteArray(0)
        ): ByteArray {
            val ipHeaderLength = 20
            val paddedOptionsLength = ((tcpOptions.size + 3) / 4) * 4
            val tcpHeaderLength = 20 + paddedOptionsLength
            val totalLength = ipHeaderLength + tcpHeaderLength + payload.size
            val out = ByteArray(totalLength)

            out[0] = 0x45
            out[1] = 0
            writeU16(out, 2, totalLength)
            writeU16(out, 4, 0)
            writeU16(out, 6, 0)
            out[8] = 64
            out[9] = 6
            request.destinationAddress.address.copyInto(out, 12)
            request.sourceAddress.address.copyInto(out, 16)
            writeU16(out, 10, checksum(out, 0, ipHeaderLength))

            val tcpOffset = ipHeaderLength
            writeU16(out, tcpOffset, request.destinationPort)
            writeU16(out, tcpOffset + 2, request.sourcePort)
            writeU32(out, tcpOffset + 4, sequenceNumber)
            writeU32(out, tcpOffset + 8, acknowledgementNumber)
            out[tcpOffset + 12] = ((tcpHeaderLength / 4) shl 4).toByte()
            out[tcpOffset + 13] = flags.toByte()
            writeU16(out, tcpOffset + 14, 65535)
            writeU16(out, tcpOffset + 16, 0)
            writeU16(out, tcpOffset + 18, 0)
            if (tcpOptions.isNotEmpty()) tcpOptions.copyInto(out, tcpOffset + 20)
            payload.copyInto(out, tcpOffset + tcpHeaderLength)

            writeU16(out, tcpOffset + 16, tcpChecksum(out, tcpOffset, tcpHeaderLength + payload.size, request.destinationAddress.address, request.sourceAddress.address))
            return out
        }

        fun nextAck(packet: IpTcpPacket): Long {
            var increment = packet.payload.size.toLong()
            if (packet.isSyn) increment += 1
            if (packet.isFin) increment += 1
            return (packet.sequenceNumber + increment) and 0xFFFF_FFFFL
        }

        fun synthetic(
            sourceAddress: InetAddress,
            destinationAddress: InetAddress,
            sourcePort: Int,
            destinationPort: Int,
            sequenceNumber: Long,
            acknowledgementNumber: Long,
            flags: Int,
            payload: ByteArray = ByteArray(0)
        ): IpTcpPacket = IpTcpPacket(
            version = 4,
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            sequenceNumber = sequenceNumber,
            acknowledgementNumber = acknowledgementNumber,
            flags = flags,
            windowSize = 65535,
            payload = payload,
            ipHeaderLength = 20,
            tcpHeaderLength = 20
        )

        fun mssOption(mss: Int): ByteArray = byteArrayOf(
            2,
            4,
            ((mss ushr 8) and 0xFF).toByte(),
            (mss and 0xFF).toByte()
        )

        private fun readU16(data: ByteArray, offset: Int): Int =
            ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

        private fun readU32(data: ByteArray, offset: Int): Long =
            ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)

        private fun writeU16(data: ByteArray, offset: Int, value: Int) {
            data[offset] = ((value ushr 8) and 0xFF).toByte()
            data[offset + 1] = (value and 0xFF).toByte()
        }

        private fun writeU32(data: ByteArray, offset: Int, value: Long) {
            data[offset] = ((value ushr 24) and 0xFF).toByte()
            data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
            data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
            data[offset + 3] = (value and 0xFF).toByte()
        }

        private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
            var sum = 0L
            var index = offset
            val end = offset + length
            while (index + 1 < end) {
                sum += readU16(data, index).toLong()
                index += 2
            }
            if (index < end) sum += (data[index].toInt() and 0xFF).toLong() shl 8
            while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
            return sum.inv().toInt() and 0xFFFF
        }

        private fun tcpChecksum(packet: ByteArray, tcpOffset: Int, tcpLength: Int, src: ByteArray, dst: ByteArray): Int {
            val pseudo = ByteArray(12 + tcpLength)
            src.copyInto(pseudo, 0)
            dst.copyInto(pseudo, 4)
            pseudo[8] = 0
            pseudo[9] = 6
            writeU16(pseudo, 10, tcpLength)
            packet.copyInto(pseudo, 12, tcpOffset, tcpOffset + tcpLength)
            pseudo[12 + 16] = 0
            pseudo[12 + 17] = 0
            return checksum(pseudo, 0, pseudo.size)
        }
    }
}

data class TcpFlowKey(
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int
)