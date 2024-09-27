package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class Ipv6DestinationOptions(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
    val optionData: List<Ipv6Tlv> = emptyList(),
) : Ipv6ExtensionHeader(IpType.IPV6_OPTS, nextHeader, length) {
    companion object {
        const val MIN_LENGTH = 2 // next header and length with no actual option data

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6DestinationOptions {
            val optionData = mutableListOf<Ipv6Tlv>()
            val start = stream.position()
            while (stream.position() - start < length.toInt()) {
                optionData.add(Ipv6Tlv.fromStream(stream))
            }
            return Ipv6DestinationOptions(nextheader, length, optionData)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH + optionData.sumOf { it.toByteArray().size })
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        optionData.forEach {
            buffer.put(it.toByteArray())
        }
        return buffer.array()
    }
}
