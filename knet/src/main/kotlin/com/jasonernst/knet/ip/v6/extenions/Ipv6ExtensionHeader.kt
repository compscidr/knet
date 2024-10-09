package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.extenions.routing.Ipv6Routing
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
    val type: IpType,
    open var nextHeader: UByte,
    open val length: UByte, // measured in 64-bit / 8-octet units, not including the first 8 octets
) {
    /**
     * This should be called by the subclass to serialize the extension header to a byte array.
     * They can serialize their own data.
     */
    open fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(2)
        buffer.order(order)
        buffer.put(nextHeader.toByte())
        buffer.put(length.toByte())
        return buffer.array()
    }

    /**
     * Returns the actual length in bytes of the extension header
     * because the length field measures in 8-octet units.
     *
     * This just simply multiplies it by 8, so it would include
     * zero padding.
     */
    fun getExtensionLengthInBytes(): Int =
        if (type == IpType.IPV6_FRAG) {
            Ipv6Fragment.LENGTH.toInt()
        } else {
            MIN_LENGTH_BYTES + (length * 8u).toInt()
        }

    companion object {
        // since the length doesn't include the first 8 octets, we assume that we always have at
        // least 8 octets
        const val MIN_LENGTH_BYTES: Int = 8

        /**
         * The required option types: https://www.rfc-editor.org/rfc/rfc8200#page-9
         * Hop-by-Hop Options
         * Fragment
         * Destination Options
         * Routing
         * Authentication
         * Encapsulating Security Payload
         */
        val requiredExtensionHeaders =
            listOf(
                IpType.HOPOPT,
                IpType.IPV6_FRAG,
                IpType.IPV6_OPTS,
                IpType.IPV6_ROUTE,
                IpType.AH,
                IpType.ESP,
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

            // if its not in the required extension headers, we will break out of the loop
            // and return the list we've made so far. This should happen when we hit the TCP, UDP,
            // etc header
            while (currentHeader in requiredExtensionHeaders && stream.hasRemaining()) {
                if (stream.remaining() < MIN_LENGTH_BYTES) {
                    throw PacketTooShortException(
                        "Not enough bytes to read the extension header, " +
                            "require: $MIN_LENGTH_BYTES, remaining: ${stream.remaining()}",
                    )
                }
                val nextHeader = stream.get().toUByte()
                val length = stream.get().toUByte()

                when (currentHeader) {
                    IpType.HOPOPT -> {
                        println("GOT HOP BY HOP with next header: $nextHeader and length $length")
                        extensionList.add(Ipv6HopByHopOptions.fromStream(stream, nextHeader, length))
                    }
                    IpType.IPV6_FRAG -> {
                        println("GOT FRAGMENT with next header: $nextHeader and length $length")
                        extensionList.add(Ipv6Fragment.fromStream(stream, nextHeader))
                    }
                    IpType.IPV6_OPTS -> {
                        extensionList.add(Ipv6DestinationOptions.fromStream(stream, nextHeader, length))
                    }
                    IpType.IPV6_ROUTE -> {
                        extensionList.add(Ipv6Routing.Companion.fromStream(stream, nextHeader, length))
                    }
                    IpType.AH -> {
                        extensionList.add(Ipv6Authentication.fromStream(stream, nextHeader, length))
                    }
                    IpType.ESP -> {
                        extensionList.add(Ipv6EncapsulatingSecurityPayload.fromStream(stream, nextHeader, length))
                    }
                    else -> {
                        // can't really get here, but kotlin requires an else case
                        throw IllegalArgumentException("Unsupported IPv6 extension header: $currentHeader")
                    }
                }
                currentHeader = IpType.fromValue(nextHeader)
            }
            return extensionList
        }
    }
}
