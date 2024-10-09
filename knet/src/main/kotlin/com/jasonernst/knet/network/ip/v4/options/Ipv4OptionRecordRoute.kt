package com.jasonernst.knet.network.ip.v4.options

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
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

 * If the route data area is already full (the pointer exceeds the
 * length) the datagram is forwarded without inserting the address
 * into the recorded route.  If there is some room but not enough
 * room for a full address to be inserted, the original datagram is
 * considered to be in error and is discarded.  In either case an
 * ICMP parameter problem message may be sent to the source
 * host [3].

 * Not copied on fragmentation, goes in first fragment only.
 * Appears at most once in a datagram.
 */
data class Ipv4OptionRecordRoute(
    override val isCopied: Boolean = false,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.RecordRoute,
    val pointer: UByte,
    val routeData: ByteArray = ByteArray(0),
) : Ipv4Option(isCopied = isCopied, optionClass = optionClass, type = type, size = (MIN_OPTION_SIZE + routeData.size.toUByte()).toUByte()) {
    companion object {
        val MIN_OPTION_SIZE: UByte = 3u
        private val logger = LoggerFactory.getLogger(Ipv4OptionRecordRoute::class.java)

        fun fromStream(
            stream: ByteBuffer,
            isCopied: Boolean,
            optionClass: Ipv4OptionClassType,
            size: UByte,
        ): Ipv4OptionRecordRoute {
            logger.debug("SIZE: $size, remaining: ${stream.remaining()}")
            if (stream.remaining() < (size - 2u).toInt()) {
                throw PacketTooShortException(
                    "Stream must have at least ${size - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionRecordRoute, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val pointer = stream.get().toUByte()
            val dataLength = size.toInt() - MIN_OPTION_SIZE.toInt()
            val routingData = ByteArray(dataLength)
            stream.get(routingData)
            return Ipv4OptionRecordRoute(
                isCopied = isCopied,
                optionClass = optionClass,
                pointer = pointer,
                routeData = routingData,
            )
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer =
            ByteBuffer
                .allocate(MIN_OPTION_SIZE.toInt() + routeData.size)
                .order(order)
                .put(super.toByteArray(order))
                .put(pointer.toByte())
                .put(routeData)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ipv4OptionRecordRoute

        if (isCopied != other.isCopied) return false
        if (optionClass != other.optionClass) return false
        if (type != other.type) return false
        if (pointer != other.pointer) return false
        if (!routeData.contentEquals(other.routeData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isCopied.hashCode()
        result = 31 * result + optionClass.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + pointer.hashCode()
        result = 31 * result + routeData.contentHashCode()
        return result
    }
}
