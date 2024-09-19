package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Defines a type-length-value (TLV) extension header for IPv6 packets. Note that not all of the
 * well-defined Ipv6 extension headers support this.
 *
 * https://datatracker.ietf.org/doc/html/rfc8200#section-4.1
 * https://www.rfc-editor.org/rfc/rfc6564#page-4
 * https://www.rfc-editor.org/rfc/rfc7045.html
 *
 * Suggested extension header order:
 * IPv6 header
 * Hop-by-Hop Options header
 * Destination Options header (note 1)
 * Routing header
 * Fragment header
 * Authentication header (note 2)
 * Encapsulating Security Payload header (note 2)
 * Destination Options header (note 3)
 * Upper-Layer header
 *
 *       note 1: for options to be processed by the first destination that
 *               appears in the IPv6 Destination Address field plus
 *               subsequent destinations listed in the Routing header.
 *
 *       note 2: additional recommendations regarding the relative order of
 *               the Authentication and Encapsulating Security Payload
 *               headers are given in [RFC4303].
 *
 *       note 3: for options to be processed only by the final destination
 *               of the packet.
 *
 * Each extension header should occur at most once, except for the
 * Destination Options header, which should occur at most twice (once
 * before a Routing header and once before the upper-layer header).
 *
 * If the upper-layer header is another IPv6 header (in the case of IPv6
 * being tunneled over or encapsulated in IPv6), it may be followed by
 * its own extension headers, which are separately subject to the same
 * ordering recommendations.
 *
 * If and when other extension headers are defined, their ordering
 * constraints relative to the above listed headers must be specified.
 *
 * IPv6 nodes must accept and attempt to process extension headers in
 * any order and occurring any number of times in the same packet,
 * except for the Hop-by-Hop Options header, which is restricted to
 * appear immediately after an IPv6 header only.  Nonetheless, it is
 * strongly advised that sources of IPv6 packets adhere to the above
 * recommended order until and unless subsequent specifications revise
 * that recommendation.
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
