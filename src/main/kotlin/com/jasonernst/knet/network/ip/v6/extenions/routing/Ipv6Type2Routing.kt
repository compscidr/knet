package com.jasonernst.knet.network.ip.v6.extenions.routing

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6ExtensionHeader.Companion.MIN_LENGTH_BYTES
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://www.rfc-editor.org/rfc/rfc6275.html#section-6.4
 *
 * The type 2 routing header has the following format:
 *
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |  Next Header  | Hdr Ext Len=2 | Routing Type=2|Segments Left=1|
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                            Reserved                           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                                                               |
 *        +                                                               +
 *        |                                                               |
 *        +                         Home Address                          +
 *        |                                                               |
 *        +                                                               +
 *        |                                                               |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    Next Header
 *
 *       8-bit selector.  Identifies the type of header immediately
 *       following the routing header.  Uses the same values as the IPv6
 *       Next Header field [6].
 *
 *    Hdr Ext Len
 *
 *       2 (8-bit unsigned integer); length of the routing header in
 *       8-octet units, not including the first 8 octets.
 *
 *    Routing Type
 *
 *       2 (8-bit unsigned integer).
 *
 *    Segments Left
 *
 *       1 (8-bit unsigned integer).
 *
 *    Reserved
 *
 *       32-bit reserved field.  The value MUST be initialized to zero by
 *       the sender, and MUST be ignored by the receiver.
 *
 *    Home Address
 *
 *       The home address of the destination mobile node.
 *
 *    For a type 2 routing header, the Hdr Ext Len MUST be 2.  The Segments
 *    Left value describes the number of route segments remaining, i.e.,
 *    number of explicitly listed intermediate nodes still to be visited
 *    before reaching the final destination.  Segments Left MUST be 1.  The
 *    ordering rules for extension headers in an IPv6 packet are described
 *    in Section 4.1 of RFC 2460 [6].  The type 2 routing header defined
 *    for Mobile IPv6 follows the same ordering as other routing headers.
 *    If another routing header is present along with a type 2 routing
 *    header, the type 2 routing header should follow the other routing
 *    header.  A packet containing such nested encapsulation should be
 *    created as if the inner (type 2) routing header was constructed first
 *    and then treated as an original packet by header construction process
 *    for the other routing header.
 *
 *    In addition, the general procedures defined by IPv6 for routing
 *    headers suggest that a received routing header MAY be automatically
 *    "reversed" to construct a routing header for use in any response
 *    packets sent by upper-layer protocols, if the received packet is
 *    authenticated [6].  This MUST NOT be done automatically for type 2
 *    routing headers.
 */
data class Ipv6Type2Routing(
    override var nextHeader: UByte = IpType.TCP.value,
    val homeAddress: ByteArray,
) : Ipv6Routing(
        nextHeader = nextHeader,
        length = 2u,
        routingType = Ipv6RoutingType.Type2RoutingHeader,
        segmentsLeft = 1u,
    ) {
    init {
        if (homeAddress.size != 16) {
            throw IllegalArgumentException("Home address must be 16 bytes, but got ${homeAddress.size}")
        }
    }

    companion object {
        fun fromStream(
            nextHeader: UByte,
            length: UByte,
            routingType: Ipv6RoutingType,
            segmentsLeft: UByte,
            stream: ByteBuffer,
        ): Ipv6Type2Routing {
            val expectedRemaining = 4 + (length * 8u).toInt()
            if (stream.remaining() < expectedRemaining) {
                throw PacketTooShortException("Expected $expectedRemaining bytes, but only have ${stream.remaining()} bytes")
            }
            if (routingType != Ipv6RoutingType.Type2RoutingHeader) {
                throw IllegalArgumentException("Expected routing type 2, but got $routingType")
            }
            if (segmentsLeft.toUInt() != 1u) {
                throw IllegalArgumentException("Expected segments left to be 1, but got $segmentsLeft")
            }
            stream.position(stream.position() + 4) // skip reserved field
            val homeAddress = ByteArray(16)
            stream.get(homeAddress)
            return Ipv6Type2Routing(nextHeader, homeAddress)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH_BYTES + (length * 8u).toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.put(homeAddress)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Ipv6Type2Routing) return false

        if (nextHeader != other.nextHeader) return false
        if (!homeAddress.contentEquals(other.homeAddress)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nextHeader.hashCode()
        result = 31 * result + homeAddress.contentHashCode()
        return result
    }
}
