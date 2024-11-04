package com.jasonernst.knet.application.dns

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
 */
data class DnsQuestion(
    var qNames: List<DnsQName>,
    var qType: DnsType,
    var qClass: DnsQClass,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(DnsQuestion::class.java)

        fun fromStream(
            stream: ByteBuffer,
            start: UShort,
        ): DnsQuestion {
            val qNames = DnsQName.fromStream(stream, start)

            // we need 2 shorts
            if (stream.remaining() < 4) {
                throw PacketTooShortException("Not enough bytes to parse a DNS question, need at least 4, have ${stream.remaining()}")
            }
            val qType = stream.short.toUShort()
            val qClass = stream.short.toUShort()
            logger.debug("Parsed DNS question: {}, {}, {}", qNames, qType, qClass)
            return DnsQuestion(qNames, DnsType.fromValue(qType), DnsQClass.fromValue(qClass))
        }
    }

    fun size(): Short {
        return (qNames.sumOf { it.getLength().toInt() } + 5).toShort() // name length + 0byte + 2 shorts
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(this.size().toInt())
        buffer.order(order)
        buffer.put(qNames.map { it.toByteArray(order) }.reduce { acc, bytes -> acc + bytes })
        buffer.put(0) // 0 byte to indicate end of qName
        buffer.putShort(qType.value.toShort())
        buffer.putShort(qClass.value.toShort())
        return buffer.array()
    }
}
