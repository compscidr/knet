package com.jasonernst.knet.ip.v6.extenions.routing

import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.extenions.Ipv6ExtensionHeader
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
open class Ipv6Routing(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
    val routingType: Ipv6RoutingType,
    val segmentsLeft: UByte = 0u,
) : Ipv6ExtensionHeader(IpType.IPV6_ROUTE, nextHeader, length) {
    companion object {
        fun fromStream(
            stream: ByteBuffer,
            nextHeader: UByte,
            length: UByte,
        ): Ipv6Routing {
            val routingType = Ipv6RoutingType.fromKind(stream.get().toUByte())
            val segmentsLeft = stream.get().toUByte()

            when (routingType) {
                Ipv6RoutingType.SourceRouteDeprecated -> {
                    // https://www.rfc-editor.org/rfc/rfc5095.html
                    // An IPv6 node that receives a packet with a destination address
                    //   assigned to it and that contains an RH0 extension header MUST NOT
                    //   execute the algorithm specified in the latter part of Section 4.4 of
                    //   [RFC2460] for RH0.  Instead, such packets MUST be processed according
                    //   to the behaviour specified in Section 4.4 of [RFC2460] for a datagram
                    //   that includes an unrecognised Routing Type value, namely:
                    //
                    //      If Segments Left is zero, the node must ignore the Routing header
                    //      and proceed to process the next header in the packet, whose type
                    //      is identified by the Next Header field in the Routing header.
                    //
                    //      If Segments Left is non-zero, the node must discard the packet and
                    //      send an ICMP Parameter Problem, Code 0, message to the packet's
                    //      Source Address, pointing to the unrecognized Routing Type.
                    //
                    //   IPv6 implementations are no longer required to implement RH0 in any
                    //   way.
                    if (segmentsLeft.toInt() == 0) {
                        val remaining = (length.toInt() * 8)
                        stream.position(stream.position() + remaining)
                        throw NonFatalRoutingException("SourceRouteDeprecated is deprecated")
                    } else {
                        throw FatalRoutingException("SourceRouteDeprecated is deprecated")
                    }
                }
                Ipv6RoutingType.NimrodDeprecated -> {
                    // https://www.rfc-editor.org/rfc/rfc2775.html
                    // The Nimrod Routing Header is deprecated and MUST NOT be used.
                    throw FatalRoutingException("NimrodDeprecated is deprecated")
                }
                Ipv6RoutingType.Type2RoutingHeader -> return Ipv6Type2Routing.fromStream(
                    nextHeader,
                    length,
                    routingType,
                    segmentsLeft,
                    stream,
                )
                // TODO: there's 6 more routing types to implement here
                else -> throw IllegalArgumentException("Unsupported routing type: $routingType")
            }
        }
    }

    /**
     * This will only put the common fields of the routing header, any type-specific data must be
     * handled by the subclass.
     */
    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH_BYTES.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.put(routingType.kind.toByte())
        buffer.put(segmentsLeft.toByte())
        return buffer.array()
    }
}
