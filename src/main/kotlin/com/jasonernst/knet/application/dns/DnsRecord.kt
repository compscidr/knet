package com.jasonernst.knet.application.dns

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
 */
data class DnsRecord(
    var qNames: List<DnsQName>,
    var type: DnsType,
    var ttl: UInt,
    var rData: DnsRData,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(DnsRecord::class.java)

        fun fromStream(
            stream: ByteBuffer,
            start: UShort,
        ): DnsRecord {
            logger.debug("Position: ${stream.position()}, limit: ${stream.limit()}")
            val qNames = DnsQName.fromStream(stream, start)
            logger.debug("GOT labels $qNames")
            // we need 3 shorts + 1 = 10
            if (stream.remaining() < 10) {
                throw PacketTooShortException("Not enough bytes to determine DNSRecord RDATA length, need 10, have ${stream.remaining()}")
            }
            logger.debug("Position: ${stream.position()}")
            val qType = stream.short.toUShort()
            val qClass = stream.short.toUShort()
            logger.debug("GOT qType $qType, qClass $qClass")
            val ttl = stream.int.toUInt()
            val rData = DnsRData.fromStream(stream, DnsType.fromValue(qType))
            return DnsRecord(qNames, DnsType.fromValue(qType), ttl, rData)
        }
    }

    fun size(): Short {
        return (qNames.sumOf { it.getLength().toInt() } + 4 + rData.size()).toShort() // names length + 2 shorts + rData size
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(this.size().toInt())
        buffer.order(order)
        buffer.put(qNames.map { it.toByteArray(order) }.reduce { acc, bytes -> acc + bytes })
        buffer.putShort(type.value.toShort())
        buffer.putInt(ttl.toInt())
        buffer.put(rData.toByteArray(order))
        return buffer.array()
    }
}
