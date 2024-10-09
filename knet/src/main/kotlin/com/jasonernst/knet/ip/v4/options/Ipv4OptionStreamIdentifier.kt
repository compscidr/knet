package com.jasonernst.knet.ip.v4.options

import com.jasonernst.knet.PacketTooShortException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * From the RFC 791:
 *
 * The record route option provides a means to record the route of
 * an internet datagram.
 *
 * The option begins with the option type code.  The second octet
 * is the option length which includes the option type code and the
 * length octet, the pointer octet, and length-3 octets of route
 * data.  The third octet is the pointer into the route data
 * indicating the octet which begins the next area to store a route
 * address.  The pointer is relative to this option, and the
 * smallest legal value for the pointer is 4.
 *
 * A recorded route is composed of a series of internet addresses.
 * Each internet address is 32 bits or 4 octets.  If the pointer is
 *
 * greater than the length, the recorded route data area is full.
 * The originating host must compose this option with a large
 * enough route data area to hold all the address expected.  The
 * size of the option does not change due to adding addresses.  The
 * intitial contents of the route data area must be zero.
 *
 * When an internet module routes a datagram it checks to see if
 * the record route option is present.  If it is, it inserts its
 * own internet address as known in the environment into which this
 * datagram is being forwarded into the recorded route begining at
 * the octet indicated by the pointer, and increments the pointer
 * by four.
 *
 * If the route data area is already full (the pointer exceeds the
 * length) the datagram is forwarded without inserting the address
 * into the recorded route.  If there is some room but not enough
 * room for a full address to be inserted, the original datagram is
 * considered to be in error and is discarded.  In either case an
 * ICMP parameter problem message may be sent to the source
 * host [3].
 *
 * Not copied on fragmentation, goes in first fragment only.
 * Appears at most once in a datagram.
 */
data class Ipv4OptionStreamIdentifier(
    override val isCopied: Boolean = true,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.StreamId,
    val streamId: UShort,
) : Ipv4Option(isCopied = isCopied, optionClass = optionClass, type = type, size = MIN_OPTION_SIZE) {
    companion object {
        const val MIN_OPTION_SIZE: UByte = 4u // two bytes for the type, size, two for the stremaid

        fun fromStream(
            stream: ByteBuffer,
            isCopied: Boolean,
            optionClass: Ipv4OptionClassType,
            size: UByte,
        ): Ipv4OptionStreamIdentifier {
            if (stream.remaining() < (size - 2u).toInt()) {
                throw PacketTooShortException(
                    "Stream must have at least ${size - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionStreamIdentifier, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val streamId = stream.short.toUShort()
            return Ipv4OptionStreamIdentifier(
                isCopied = isCopied,
                optionClass = optionClass,
                streamId = streamId,
            )
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(size.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.putShort(streamId.toShort())
        return buffer.array()
    }
}
