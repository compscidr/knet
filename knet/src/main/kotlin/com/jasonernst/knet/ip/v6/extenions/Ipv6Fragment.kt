package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.and

/**
 *
 * The Fragment header is used by an IPv6 source to send a packet larger
 * than would fit in the path MTU to its destination.  (Note: unlike
 * IPv4, fragmentation in IPv6 is performed only by source nodes, not by
 * routers along a packet's delivery path -- see Section 5.)  The
 * Fragment header is identified by a Next Header value of 44 in the
 * immediately preceding header and has the following format:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Identification                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Next Header         8-bit selector.  Identifies the initial header
 * type of the Fragmentable Part of the original
 * packet (defined below).  Uses the same values
 * as the IPv4 Protocol field [IANA-PN].
 *
 * Reserved            8-bit reserved field.  Initialized to zero for
 * transmission; ignored on reception.
 *
 * Fragment Offset     13-bit unsigned integer.  The offset, in
 * 8-octet units, of the data following this
 * header, relative to the start of the
 * Fragmentable Part of the original packet.
 *
 * Res                 2-bit reserved field.  Initialized to zero for
 * transmission; ignored on reception.
 *
 * M flag              1 = more fragments; 0 = last fragment.
 *
 * Identification      32 bits.  See description below.
 *
 * In order to send a packet that is too large to fit in the MTU of the
 * path to its destination, a source node may divide the packet into
 * fragments and send each fragment as a separate packet, to be
 * reassembled at the receiver.
 *
 * For every packet that is to be fragmented, the source node generates
 * an Identification value.  The Identification must be different than
 * that of any other fragmented packet sent recently* with the same
 * Source Address and Destination Address.  If a Routing header is
 * present, the Destination Address of concern is that of the final
 * destination.
 *
 * "recently" means within the maximum likely lifetime of a
 * packet, including transit time from source to destination and
 * time spent awaiting reassembly with other fragments of the same
 * packet.  However, it is not required that a source node knows
 * the maximum packet lifetime.  Rather, it is assumed that the
 * requirement can be met by implementing an algorithm that
 * results in a low identification reuse frequency.  Examples of
 * algorithms that can meet this requirement are described in
 * [RFC7739].
 *
 * The initial, large, unfragmented packet is referred to as the
 * "original packet", and it is considered to consist of three parts, as
 * illustrated:
 *
 * original packet:
 *
 * +------------------+-------------------------+---//----------------+
 * |  Per-Fragment    | Extension & Upper-Layer |   Fragmentable      |
 * |    Headers       |       Headers           |      Part           |
 * +------------------+-------------------------+---//----------------+
 *
 * The Per-Fragment headers must consist of the IPv6 header plus any
 * extension headers that must be processed by nodes en route to the
 * destination, that is, all headers up to and including the Routing
 * header if present, else the Hop-by-Hop Options header if present,
 * else no extension headers.
 *
 * The Extension headers are all other extension headers that are not
 * included in the Per-Fragment headers part of the packet.  For this
 * purpose, the Encapsulating Security Payload (ESP) is not
 * considered an extension header.  The Upper-Layer header is the
 * first upper-layer header that is not an IPv6 extension header.
 * Examples of upper-layer headers include TCP, UDP, IPv4, IPv6,
 * ICMPv6, and as noted ESP.
 *
 * The Fragmentable Part consists of the rest of the packet after the
 * upper-layer header or after any header (i.e., initial IPv6 header
 * or extension header) that contains a Next Header value of No Next
 * Header.
 *
 * The Fragmentable Part of the original packet is divided into
 * fragments.  The lengths of the fragments must be chosen such that the
 * resulting fragment packets fit within the MTU of the path to the
 * packet's destination(s).  Each complete fragment, except possibly the
 * last ("rightmost") one, is an integer multiple of 8 octets long.
 *
 * The Identification value generated for the original
 * packet.
 *
 * (3)  Extension headers, if any, and the Upper-Layer header.  These
 * headers must be in the first fragment.  Note: This restricts
 * the size of the headers through the Upper-Layer header to the
 * MTU of the path to the packet's destinations(s).
 *
 * (4)  The first fragment.
 *
 * The subsequent fragment packets are composed of:
 *
 * (1)  The Per-Fragment headers of the original packet, with the
 * Payload Length of the original IPv6 header changed to contain
 * the length of this fragment packet only (excluding the length
 * of the IPv6 header itself), and the Next Header field of the
 * last header of the Per-Fragment headers changed to 44.
 *
 * (2)  A Fragment header containing:
 *
 * The Next Header value that identifies the first header
 * after the Per-Fragment headers of the original packet.
 *
 * A Fragment Offset containing the offset of the fragment,
 * in 8-octet units, relative to the start of the
 * Fragmentable Part of the original packet.
 *
 * An M flag value of 0 if the fragment is the last
 * ("rightmost") one, else an M flag value of 1.
 *
 * The Identification value generated for the original
 * packet.
 *
 * (3)  The fragment itself.
 *
 * Fragments must not be created that overlap with any other fragments
 * created from the original packet.
 *
 * At the destination, fragment packets are reassembled into their
 * original, unfragmented form, as illustrated:
 *
 * reassembled original packet:
 *
 * +---------------+-----------------+---------+--------+-//--+--------+
 * | Per-Fragment  |Ext & Upper-Layer|  first  | second |     | last   |
 * |    Headers    |     Headers     |frag data|fragment|.....|fragment|
 * +---------------+-----------------+---------+--------+-//--+--------+
 *
 * The following rules govern reassembly:
 *
 * An original packet is reassembled only from fragment packets that
 * have the same Source Address, Destination Address, and Fragment
 * Identification.
 *
 * The Per-Fragment headers of the reassembled packet consists of all
 * headers up to, but not including, the Fragment header of the first
 * fragment packet (that is, the packet whose Fragment Offset is
 * zero), with the following two changes:
 *
 * The Next Header field of the last header of the Per-Fragment
 * headers is obtained from the Next Header field of the first
 * fragment's Fragment header.
 *
 * The Payload Length of the reassembled packet is computed from
 * the length of the Per-Fragment headers and the length and
 * offset of the last fragment.  For example, a formula for
 * computing the Payload Length of the reassembled original packet
 * is:
 *
 * PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last
 *
 * where
 * PL.orig  =  Payload Length field of reassembled packet.
 * PL.first =  Payload Length field of first fragment packet.
 * FL.first =  length of fragment following Fragment header of
 * first fragment packet.
 * FO.last  =  Fragment Offset field of Fragment header of last
 * fragment packet.
 * FL.last  =  length of fragment following Fragment header of
 * last fragment packet.
 *
 * The Fragmentable Part of the reassembled packet is constructed
 * from the fragments following the Fragment headers in each of
 * the fragment packets.  The length of each fragment is computed
 * by subtracting from the packet's Payload Length the length of
 * the headers between the IPv6 header and fragment itself; its
 *
 * relative position in Fragmentable Part is computed from its
 * Fragment Offset value.
 *
 * The Fragment header is not present in the final, reassembled
 * packet.
 *
 * If the fragment is a whole datagram (that is, both the Fragment
 * Offset field and the M flag are zero), then it does not need
 * any further reassembly and should be processed as a fully
 * reassembled packet (i.e., updating Next Header, adjust Payload
 * Length, removing the Fragment header, etc.).  Any other
 * fragments that match this packet (i.e., the same IPv6 Source
 * Address, IPv6 Destination Address, and Fragment Identification)
 * should be processed independently.
 *
 * The following error conditions may arise when reassembling fragmented
 * packets:
 *
 * o  If insufficient fragments are received to complete reassembly
 * of a packet within 60 seconds of the reception of the first-
 * arriving fragment of that packet, reassembly of that packet
 * must be abandoned and all the fragments that have been received
 * for that packet must be discarded.  If the first fragment
 * (i.e., the one with a Fragment Offset of zero) has been
 * received, an ICMP Time Exceeded -- Fragment Reassembly Time
 * Exceeded message should be sent to the source of that fragment.
 *
 * o  If the length of a fragment, as derived from the fragment
 * packet's Payload Length field, is not a multiple of 8 octets
 * and the M flag of that fragment is 1, then that fragment must
 * be discarded and an ICMP Parameter Problem, Code 0, message
 * should be sent to the source of the fragment, pointing to the
 * Payload Length field of the fragment packet.
 *
 * o  If the length and offset of a fragment are such that the
 * Payload Length of the packet reassembled from that fragment
 * would exceed 65,535 octets, then that fragment must be
 * discarded and an ICMP Parameter Problem, Code 0, message should
 * be sent to the source of the fragment, pointing to the Fragment
 * Offset field of the fragment packet.
 *
 * o  If the first fragment does not include all headers through an
 * Upper-Layer header, then that fragment should be discarded and
 * an ICMP Parameter Problem, Code 3, message should be sent to
 * the source of the fragment, with the Pointer field set to zero.
 *
 * o  If any of the fragments being reassembled overlap with any
 * other fragments being reassembled for the same packet,
 * reassembly of that packet must be abandoned and all the
 * fragments that have been received for that packet must be
 * discarded, and no ICMP error messages should be sent.
 *
 * It should be noted that fragments may be duplicated in the
 * network.  Instead of treating these exact duplicate fragments
 * as overlapping fragments, an implementation may choose to
 * detect this case and drop exact duplicate fragments while
 * keeping the other fragments belonging to the same packet.
 *
 * The following conditions are not expected to occur frequently but are
 * not considered errors if they do:
 *
 * The number and content of the headers preceding the Fragment
 * header of different fragments of the same original packet may
 * differ.  Whatever headers are present, preceding the Fragment
 * header in each fragment packet, are processed when the packets
 * arrive, prior to queueing the fragments for reassembly.  Only
 * those headers in the Offset zero fragment packet are retained in
 * the reassembled packet.
 *
 * The Next Header values in the Fragment headers of different
 * fragments of the same original packet may differ.  Only the value
 * from the Offset zero fragment packet is used for reassembly.
 *
 * Other fields in the IPv6 header may also vary across the fragments
 * being reassembled.  Specifications that use these fields may
 * provide additional instructions if the basic mechanism of using
 * the values from the Offset zero fragment is not sufficient.  For
 * example, Section 5.3 of [RFC3168] describes how to combine the
 * Explicit Congestion Notification (ECN) bits from different
 * fragments to derive the ECN bits of the reassembled packet.
 *
 * NOTE: length is overrided to 0u because that field is reserved and should be all zeros according
 * to the spec.
 */
data class Ipv6Fragment(
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = LENGTH,
    val fragmentOffset: UShort = 0u,
    val moreFlag: Boolean = false,
    val identification: UInt = 0u,
) : Ipv6ExtensionHeader(IpType.IPV6_FRAG, nextHeader = nextHeader, length = 0u) {
    companion object {
        const val LENGTH: UByte = 8u // next header, reserved, fragment offset, and identification
        var globalIdentificationCounter: UInt = 0u

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
        ): Ipv6Fragment {
            val fragmentOffsetRMByte = stream.getShort()
            val fragmentOffset = ((fragmentOffsetRMByte and 0b111111111111100).toUInt() shr 3).toUShort()
            val moreFlag = (fragmentOffsetRMByte and 0b1).toInt() == 1
            val identification = stream.getInt().toUInt()
            return Ipv6Fragment(nextheader, LENGTH, fragmentOffset, moreFlag, identification)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(LENGTH.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.putShort((fragmentOffset.toInt() shl 3 or if (moreFlag) 1 else 0).toShort())
        buffer.putInt(identification.toInt())
        return buffer.array()
    }
}
