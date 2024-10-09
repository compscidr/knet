package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.PacketTooShortException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 *
 * Two of the currently defined extension headers specified in this
 * document -- the Hop-by-Hop Options header and the Destination Options
 * header -- carry a variable number of "options" that are type-length-
 * value (TLV) encoded in the following format:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
 * |  Option Type  |  Opt Data Len |  Option Data
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
 *
 * Option Type         8-bit identifier of the type of option.
 *
 * Opt Data Len        8-bit unsigned integer.  Length of the Option
 * Data field of this option, in octets.
 *
 * Option Data         Variable-length field.  Option-Type-specific
 * data.
 *
 * The sequence of options within a header must be processed strictly in
 * the order they appear in the header; a receiver must not, for
 * example, scan through the header looking for a particular kind of
 * option and process that option prior to processing all preceding
 * ones.
 *
 * The Option Type identifiers are internally encoded such that their
 * highest-order 2 bits specify the action that must be taken if the
 * processing IPv6 node does not recognize the Option Type:
 *
 * 00 - skip over this option and continue processing the header.
 *
 * 01 - discard the packet.
 *
 * 10 - discard the packet and, regardless of whether or not the
 * packet's Destination Address was a multicast address, send an
 * ICMP Parameter Problem, Code 2, message to the packet's
 * Source Address, pointing to the unrecognized Option Type.
 *
 * 11 - discard the packet and, only if the packet's Destination
 * Address was not a multicast address, send an ICMP Parameter
 * Problem, Code 2, message to the packet's Source Address,
 * pointing to the unrecognized Option Type.
 *
 * The third-highest-order bit of the Option Type specifies whether or
 * not the Option Data of that option can change en route to the
 * packet's final destination.  When an Authentication header is present
 * in the packet, for any option whose data may change en route, its
 * entire Option Data field must be treated as zero-valued octets when
 * computing or verifying the packet's authenticating value.
 *
 * 0 - Option Data does not change en route
 *
 * 1 - Option Data may change en route
 *
 * The three high-order bits described above are to be treated as part
 * of the Option Type, not independent of the Option Type.  That is, a
 * particular option is identified by a full 8-bit Option Type, not just
 * the low-order 5 bits of an Option Type.
 *
 * The same Option Type numbering space is used for both the Hop-by-Hop
 * Options header and the Destination Options header.  However, the
 * specification of a particular option may restrict its use to only one
 * of those two headers.
 *
 * Individual options may have specific alignment requirements, to
 * ensure that multi-octet values within Option Data fields fall on
 * natural boundaries.  The alignment requirement of an option is
 * specified using the notation xn+y, meaning the Option Type must
 * appear at an integer multiple of x octets from the start of the
 * header, plus y octets.  For example:
 *
 * 2n     means any 2-octet offset from the start of the header.
 * 8n+2   means any 8-octet offset from the start of the header, plus
 * 2 octets.
 *
 * There are two padding options that are used when necessary to align
 * subsequent options and to pad out the containing header to a multiple
 * of 8 octets in length.  These padding options must be recognized by
 * all IPv6 implementations:
 *
 * Pad1 option (alignment requirement: none)
 *
 * +-+-+-+-+-+-+-+-+
 * |       0       |
 * +-+-+-+-+-+-+-+-+
 *
 * NOTE! the format of the Pad1 option is a special case -- it does
 * not have length and value fields.
 *
 * The Pad1 option is used to insert 1 octet of padding into the
 * Options area of a header.  If more than one octet of padding is
 * required, the PadN option, described next, should be used, rather
 * than multiple Pad1 options.
 *
 * PadN option (alignment requirement: none)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
 * |       1       |  Opt Data Len |  Option Data
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
 *
 * The PadN option is used to insert two or more octets of padding
 * into the Options area of a header.  For N octets of padding, the
 * Opt Data Len field contains the value N-2, and the Option Data
 * consists of N-2 zero-valued octets.
 *
 * Appendix A contains formatting guidelines for designing new options.
 */
data class Ipv6Tlv(
    val optionType: Ipv6DestinationHopByHopType = Ipv6DestinationHopByHopType.PadN,
    val optionDataLength: UByte = 4u,
    val optionData: ByteArray = ByteArray(4),
) {
    init {
        if (optionDataLength.toInt() != optionData.size) {
            throw IllegalArgumentException(
                "Option data length does not match option data size, have ${optionData.size} but expected ${optionDataLength.toInt()}",
            )
        }
    }

    companion object {
        const val MIN_TLV_LENGTH = 2
        private val logger = org.slf4j.LoggerFactory.getLogger(Ipv6Tlv::class.java)

        fun fromStream(stream: ByteBuffer): Ipv6Tlv {
            if (stream.remaining() < MIN_TLV_LENGTH) {
                throw PacketTooShortException("Stream must have at least 2 bytes remaining to parse Ipv6Tlv")
            }
            val optionType = Ipv6DestinationHopByHopType.fromKind(stream.get().toUByte())
            val optionDataLength = stream.get().toUByte()
            if (stream.remaining() < optionDataLength.toInt()) {
                throw PacketTooShortException("Stream must have at least $optionDataLength bytes remaining to parse Ipv6Tlv")
            }
            val optionData = ByteArray(optionDataLength.toInt())
            stream.get(optionData)
            return Ipv6Tlv(optionType, optionDataLength, optionData)
        }
    }

    fun size(): Int = MIN_TLV_LENGTH + optionData.size

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ipv6Tlv

        if (optionType != other.optionType) return false
        if (optionDataLength != other.optionDataLength) return false
        if (!optionData.contentEquals(other.optionData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = optionType.hashCode()
        result = 31 * result + optionDataLength.hashCode()
        result = 31 * result + optionData.contentHashCode()
        return result
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(2 + optionData.size)
        buffer.order(order)
        buffer.put(optionType.kind.toByte())
        buffer.put(optionDataLength.toByte())
        buffer.put(optionData)
        return buffer.array()
    }
}
