package com.jasonernst.knet

import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.nextheader.NextHeader
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Encapsulates everything we need a for a full packet, an IP header, a set of next headers (usually
 * only a single next header if we have an IPv4 packet, but could be more if we have an IPv6 packet
 * with hop-by-hop options, for example).
 */
data class Packet(
    val ipHeader: IpHeader,
    val nextHeaders: NextHeader,
    val payload: ByteArray,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        private val logger = LoggerFactory.getLogger(javaClass)

        fun fromStream(stream: ByteBuffer): Packet {
            val ipHeader = IpHeader.fromStream(stream)
            logger.debug("IP header: {}", ipHeader)
            val nextHeader = NextHeader.fromStream(stream, ipHeader.getNextHeaderProtocol())
            logger.debug("Next header: {}", nextHeader)
            val expectedRemaining = (ipHeader.getTotalLength() - ipHeader.getHeaderLength() - nextHeader.getHeaderLength()).toInt()
            if (stream.remaining() < expectedRemaining) {
                throw PacketTooShortException(
                    "Packet too short to obtain entire payload, have ${stream.remaining()}, expecting $expectedRemaining",
                )
            }
            val payload = ByteArray(expectedRemaining)
            stream.get(payload)
            return Packet(ipHeader, nextHeader, payload)
        }
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        logger.debug("Allocating ${ipHeader.getTotalLength()} bytes for packet")
        val buffer = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
        buffer.order(order)
        val ipHeaderBytes = ipHeader.toByteArray()
        logger.debug("Have ${ipHeaderBytes.size} bytes for IP header")
        buffer.put(ipHeaderBytes)
        val nextHeaderBytes = nextHeaders.toByteArray()
        logger.debug("Have ${nextHeaderBytes.size} bytes for next headers")
        buffer.put(nextHeaderBytes)
        logger.debug("Have ${payload.size} bytes for payload")
        buffer.put(payload)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Packet

        if (ipHeader != other.ipHeader) return false
        if (nextHeaders != other.nextHeaders) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ipHeader.hashCode()
        result = 31 * result + nextHeaders.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}
