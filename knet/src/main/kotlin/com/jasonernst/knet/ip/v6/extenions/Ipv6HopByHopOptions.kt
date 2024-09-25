package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.ceil

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
    override val nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = ceil((MIN_LENGTH.toDouble() + Ipv6Tlv().size()) / 8.0).toUInt().toUByte(),
    val optionData: List<Ipv6Tlv> = listOf(Ipv6Tlv()),
) : Ipv6ExtensionHeader(nextHeader, length) {
    init {
        // dummy check to make sure the length is a multiple of 8
        val optionLength = optionData.sumOf { it.size() }
        val totalLength = optionLength + MIN_LENGTH.toInt()
        if (totalLength % 8 != 0) {
            throw IllegalArgumentException("Option data length + 2 must be a multiple of 8, but have $totalLength")
        }

        // dummy check to ensure length matches the option data
        val octet8Lengths = ceil(totalLength.toDouble() / 8.0)
        if (octet8Lengths != length.toDouble()) {
            throw IllegalArgumentException(
                "(Option data length + 2) / 8 must match the length field, have $octet8Lengths, expecting $length",
            )
        }
    }

    companion object {
        const val MIN_LENGTH: UByte = 2u // next header and length with no actual option data

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6HopByHopOptions {
            val optionData = mutableListOf<Ipv6Tlv>()
            val start = stream.position()
            while (stream.position() - start < length.toInt()) {
                optionData.add(Ipv6Tlv.fromStream(stream))
            }
            return Ipv6HopByHopOptions(nextheader, length, optionData)
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
