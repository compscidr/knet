package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.extenions.type.Ipv6RoutingType
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://www.rfc-editor.org/rfc/rfc8200#section-4.4
 *
 * The Routing header is used by an IPv6 source to list one or more
 *    intermediate nodes to be "visited" on the way to a packet's
 *    destination.  This function is very similar to IPv4's Loose Source
 *    and Record Route option.  The Routing header is identified by a Next
 *    Header value of 43 in the immediately preceding header and has the
 *    following format:
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     .                                                               .
 *     .                       type-specific data                      .
 *     .                                                               .
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *       Next Header         8-bit selector.  Identifies the type of header
 *                           immediately following the Routing header.
 *                           Uses the same values as the IPv4 Protocol
 *                           field [IANA-PN].
 *
 *       Hdr Ext Len         8-bit unsigned integer.  Length of the Routing
 *                           header in 8-octet units, not including the
 *                           first 8 octets.
 *
 *       Routing Type        8-bit identifier of a particular Routing
 *                           header variant.
 *
 *       Segments Left       8-bit unsigned integer.  Number of route
 *                           segments remaining, i.e., number of explicitly
 *                           listed intermediate nodes still to be visited
 *                           before reaching the final destination.
 *
 *       type-specific data  Variable-length field, of format determined by
 *                           the Routing Type, and of length such that the
 *                           complete Routing header is an integer multiple
 *                           of 8 octets long.
 *
 *    If, while processing a received packet, a node encounters a Routing
 *    header with an unrecognized Routing Type value, the required behavior
 *    of the node depends on the value of the Segments Left field, as
 *    follows:
 *
 *       If Segments Left is zero, the node must ignore the Routing header
 *       and proceed to process the next header in the packet, whose type
 *       is identified by the Next Header field in the Routing header.
 *
 *       If Segments Left is non-zero, the node must discard the packet and
 *       send an ICMP Parameter Problem, Code 0, message to the packet's
 *       Source Address, pointing to the unrecognized Routing Type.
 *
 *    If, after processing a Routing header of a received packet, an
 *    intermediate node determines that the packet is to be forwarded onto
 *    a link whose link MTU is less than the size of the packet, the node
 *    must discard the packet and send an ICMP Packet Too Big message to
 *    the packet's Source Address.
 *
 *    The currently defined IPv6 Routing Headers and their status can be
 *    found at [IANA-RH].  Allocation guidelines for IPv6 Routing Headers
 *    can be found in [RFC5871].
 */
data class Ipv6Routing(
    override val nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = MIN_LENGTH,
    val routingType: Ipv6RoutingType,
    val segmentsLeft: UByte,
) : Ipv6ExtensionHeader(nextHeader, length) {
    companion object {
        const val MIN_LENGTH: UByte = 4u // next header, length, routing type, and segments left

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6Routing {
            val routingType = Ipv6RoutingType.fromKind(stream.get().toUByte())
            val segmentsLeft = stream.get().toUByte()
            return Ipv6Routing(nextheader, length, routingType, segmentsLeft)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.put(routingType.kind.toByte())
        buffer.put(segmentsLeft.toByte())
        return buffer.array()
    }
}
