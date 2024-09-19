package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Defines a type-length-value (TLV) extension header for IPv6 packets. Note that not all of the
 * well-defined Ipv6 extension headers support this.
 *
 * https://www.rfc-editor.org/rfc/rfc6564#page-4
 * https://www.rfc-editor.org/rfc/rfc7045.html
 */
open class Ipv6ExtensionHeader(
    open val nextHeader: UByte,
    open val length: UByte,
    open val data: ByteArray,
) {
    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(2 + data.size * 8)
        buffer.order(order)
        buffer.put(nextHeader.toByte())
        buffer.put(length.toByte())
        buffer.put(data)
        return buffer.array()
    }

    fun getExtensionLength(): Int = 2 + data.size * 8

    companion object {
        /**
         * The required option types: https://www.rfc-editor.org/rfc/rfc8200#page-9
         * Hop-by-Hop Options
         * Fragment
         * Destination Options
         * Routing
         * Authentication
         * Encapsulating Security Payload
         */
        val requiredExtensionHeaders = listOf(
            IpType.HOPOPT,
            IpType.IPV6_FRAG,
            IpType.IPV6_OPTS,
            IpType.IPV6_ROUTE,
            IpType.AH,
            IpType.ESP
        )

        /**
         * This will continue to process IPv6 extension headers until the nextheader is not one, ie)
         * it is TCP, UDP, ICMP or something
         */
        fun fromStream(
            stream: ByteBuffer,
            firstHeader: IpType,
        ): List<Ipv6ExtensionHeader> {
            var currentHeader = firstHeader
            val extensionList = mutableListOf<Ipv6ExtensionHeader>()
            while (currentHeader in requiredExtensionHeaders) {
                if (stream.remaining() < 2) {
                    throw PacketTooShortException("Not enough bytes remaining to determine the length")
                }
                val nextHeader = stream.get().toUByte()
                val length = stream.get().toUByte()
                val data = ByteArray(length.toInt() * 8)
                stream.get(data)

                when (currentHeader) {
                    IpType.HOPOPT -> {
                        extensionList.add(Ipv6HopByHopOptions(nextHeader, length, data))
                    }
                    else -> {
                        throw IllegalArgumentException("Unsupported IPv6 extension header: $currentHeader")
                    }
                }

                currentHeader = IpType.fromValue(nextHeader)
            }
            return extensionList
        }
    }
}
