package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpType
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class Ipv6DestinationOptions(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = MIN_LENGTH,
    val optionData: List<Ipv6Tlv> = emptyList(),
) : Ipv6ExtensionHeader(IpType.IPV6_OPTS, nextHeader, length) {
    companion object {
        val logger = LoggerFactory.getLogger(Ipv6DestinationOptions::class.java)
        const val MIN_LENGTH: UByte = 2u // next header and length with no actual option data

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6DestinationOptions {
            val optionData = mutableListOf<Ipv6Tlv>()
            val start = stream.position()
            logger.debug("Stream position: ${stream.position()} remaining: ${stream.remaining()}")
            if (stream.remaining() < (length.toInt() - MIN_LENGTH.toInt())) {
                throw PacketTooShortException("We require: ${length - MIN_LENGTH} bytes left but only have ${stream.remaining()} bytes left")
            }
            while (stream.position() - start < length.toInt() - MIN_LENGTH.toInt()) {
                optionData.add(Ipv6Tlv.fromStream(stream))
            }
            return Ipv6DestinationOptions(nextheader, length, optionData)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH.toInt() + optionData.sumOf { it.toByteArray().size })
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        optionData.forEach {
            buffer.put(it.toByteArray())
        }
        return buffer.array()
    }
}
