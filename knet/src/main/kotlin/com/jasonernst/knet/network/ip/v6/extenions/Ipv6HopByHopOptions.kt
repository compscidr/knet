package com.jasonernst.knet.network.ip.v6.extenions

import com.jasonernst.knet.network.ip.IpType
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://www.rfc-editor.org/rfc/rfc8200#page-13
 *
 * The Hop-by-Hop Options header is used to carry optional information
 *    that may be examined and processed by every node along a packet's
 *    delivery path.  The Hop-by-Hop Options header is identified by a Next
 *    Header value of 0 in the IPv6 header and has the following format:
 *
 *  Next Header         8-bit selector.  Identifies the type of header
 *                           immediately following the Hop-by-Hop Options
 *                           header.  Uses the same values as the IPv4
 *                           Protocol field [IANA-PN]
 *
 *  Hdr Ext Len         8-bit unsigned integer.  Length of the
 *                           Hop-by-Hop Options header in 8-octet units,
 *                           not including the first 8 octets.
 *
 *  Variable-length field, of length such that the
 *                           complete Hop-by-Hop Options header is an
 *                           integer multiple of 8 octets long.  Contains
 *                           one or more TLV-encoded options, as described
 *                           in Section 4.2.
 */
data class Ipv6HopByHopOptions(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
    val optionData: List<Ipv6Tlv> = listOf(Ipv6Tlv()),
) : Ipv6ExtensionHeader(IpType.HOPOPT, nextHeader, length) {
    private val logger = LoggerFactory.getLogger(javaClass)

    init {
        // dummy check to ensure length matches the option data
        val optionDataLength = optionData.sumOf { it.size() }
        val fullLength = 2 + optionDataLength
        val octet8Lengths = (fullLength / 8.0) - 1
        if (octet8Lengths != length.toDouble()) {
            throw IllegalArgumentException("(Option data length / 8 must match the length field, have $octet8Lengths, expecting $length")
        }
    }

    companion object {
        /**
         * Assumes that the stream has already had the nextHeader and length parsed from it
         */
        fun fromStream(
            stream: ByteBuffer,
            nextHeader: UByte,
            length: UByte,
        ): Ipv6HopByHopOptions {
            val limit = (((length + 1u) * 8u) - 2u).toInt()
            val optionData = mutableListOf<Ipv6Tlv>()
            val start = stream.position()
            while (stream.position() - start < limit) {
                val nextTlv = Ipv6Tlv.fromStream(stream)
                optionData.add(nextTlv)
            }
            return Ipv6HopByHopOptions(nextHeader, length, optionData)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(getExtensionLengthInBytes())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        optionData.forEach {
            buffer.put(it.toByteArray())
        }
        return buffer.array()
    }
}
