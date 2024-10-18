package com.jasonernst.knet.datalink

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bare minimal Ethernet frame.
 *
 * https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9844436
 * https://en.wikipedia.org/wiki/Ethernet_frame
 *
 * Note, there are lots of missing fields - because the OS doesn't present them to upper layers.
 * All we get are the source and destination MAC addresses, and the EtherType (or size).
 *
 */
data class EthernetHeader(
    val destination: MacAddress = MacAddress.DUMMY_MAC_DEST,
    val source: MacAddress = MacAddress.DUMMY_MAC_SOURCE,
    val type: EtherType = EtherType.IPv4,
) {
    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(ETHERNET_HEADER_LENGTH.toInt())
        buffer.order(order)
        buffer.put(destination.bytes)
        buffer.put(source.bytes)
        buffer.putShort(type.value.toShort())
        return buffer.array()
    }

    override fun toString(): String = "EthernetHeader(destination=$destination, source=$source, type=$type, size=${ETHERNET_HEADER_LENGTH})"

    companion object {
        const val ETHERNET_HEADER_LENGTH = 14u

        fun fromStream(stream: ByteBuffer): EthernetHeader {
            val destination = MacAddress.fromStream(stream)
            val source = MacAddress.fromStream(stream)
            val type = EtherType.fromValue(stream.short.toUShort())
            return EthernetHeader(destination, source, type)
        }
    }
}
