package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The Destination Options header is used to carry optional information
 *    that need be examined only by a packet's destination node(s).  The
 *    Destination Options header is identified by a Next Header value of 60
 *    in the immediately preceding header and has the following format:
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  Next Header  |  Hdr Ext Len  |                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *     |                                                               |
 *     .                                                               .
 *     .                            Options                            .
 *     .                                                               .
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *       Next Header         8-bit selector.  Identifies the type of header
 *                           immediately following the Destination Options
 *                           header.  Uses the same values as the IPv4
 *                           Protocol field [IANA-PN].
 *
 *       Hdr Ext Len         8-bit unsigned integer.  Length of the
 *                           Destination Options header in 8-octet units,
 *                           not including the first 8 octets.
 *
 *       Options             Variable-length field, of length such that the
 *                           complete Destination Options header is an
 *                           integer multiple of 8 octets long.  Contains
 *                           one or more TLV-encoded options, as described
 *                           in Section 4.2.
 *
 *    The only destination options defined in this document are the Pad1
 *    and PadN options specified in Section 4.2.
 *
 *    Note that there are two possible ways to encode optional destination
 *    information in an IPv6 packet: either as an option in the Destination
 *    Options header or as a separate extension header.  The Fragment
 *    header and the Authentication header are examples of the latter
 *    approach.  Which approach can be used depends on what action is
 *    desired of a destination node that does not understand the optional
 *    information:
 *
 *       o  If the desired action is for the destination node to discard
 *          the packet and, only if the packet's Destination Address is not
 *          a multicast address, send an ICMP Unrecognized Type message to
 *          the packet's Source Address, then the information may be
 *          encoded either as a separate header or as an option in the
 *          Destination Options header whose Option Type has the value 11
 *          in its highest-order 2 bits.  The choice may depend on such
 *          factors as which takes fewer octets, or which yields better
 *          alignment or more efficient parsing.
 *
 *       o  If any other action is desired, the information must be encoded
 *          as an option in the Destination Options header whose Option
 *          Type has the value 00, 01, or 10 in its highest-order 2 bits,
 *          specifying the desired action (see Section 4.2).
 */
data class Ipv6DestinationOptions(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
    val optionData: List<Ipv6Tlv> = listOf(Ipv6Tlv()),
) : Ipv6ExtensionHeader(IpType.IPV6_OPTS, nextHeader, length) {
    private val logger = LoggerFactory.getLogger(javaClass)

    init {
        // dummy check to ensure length matches the option data
        val optionDataLength = optionData.sumOf { it.size() }
        logger.debug("Option data length: {}", optionDataLength)
        val fullLength = 2 + optionDataLength
        logger.debug("Full length: {}", fullLength)
        val octet8Lengths = (fullLength / 8.0) - 1
        if (octet8Lengths != length.toDouble()) {
            throw IllegalArgumentException("(Option data length / 8 must match the length field, have $octet8Lengths, expecting $length")
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(Ipv6DestinationOptions::class.java)

        /**
         * Assumes that the stream has already had the nextHeader and length parsed from it
         */
        fun fromStream(
            stream: ByteBuffer,
            nextHeader: UByte,
            length: UByte,
        ): Ipv6DestinationOptions {
            val limit = (((length + 1u) * 8u) - 2u).toInt()
            val optionData = mutableListOf<Ipv6Tlv>()
            val start = stream.position()
            logger.debug("LENGTH: {} POSITION: {} LIMIT: {}", length, start, limit)
            while (stream.position() - start < limit) {
                val nextTlv = Ipv6Tlv.fromStream(stream)
                logger.debug("Parsed TLV: {}", nextTlv)
                optionData.add(nextTlv)
            }
            return Ipv6DestinationOptions(nextHeader, length, optionData)
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
