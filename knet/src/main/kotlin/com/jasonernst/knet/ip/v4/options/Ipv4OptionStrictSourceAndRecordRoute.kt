package com.jasonernst.knet.ip.v4.options

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * From RFC 791:
 *
 * The strict source and record route (SSRR) option provides a
 * means for the source of an internet datagram to supply routing
 * information to be used by the gateways in forwarding the
 * datagram to the destination, and to record the route
 * information.
 *
 * The option begins with the option type code.  The second octet
 * is the option length which includes the option type code and the
 * length octet, the pointer octet, and length-3 octets of route
 * data.  The third octet is the pointer into the route data
 * indicating the octet which begins the next source address to be
 * processed.  The pointer is relative to this option, and the
 * smallest legal value for the pointer is 4.
 *
 * A route data is composed of a series of internet addresses.
 * Each internet address is 32 bits or 4 octets.  If the pointer is
 * greater than the length, the source route is empty (and the
 * recorded route full) and the routing is to be based on the
 * destination address field.
 */
data class Ipv4OptionStrictSourceAndRecordRoute(
    override val isCopied: Boolean = true,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.StrictSourceRouting,
    val pointer: UByte,
    val routeData: ByteArray = ByteArray(0),
) : Ipv4Option(isCopied, optionClass, type, size = (routeData.size.toUByte() + MIN_OPTION_SIZE).toUByte()) {
    companion object {
        val MIN_OPTION_SIZE: UByte = 3u
        private val logger = LoggerFactory.getLogger(Ipv4OptionStrictSourceAndRecordRoute::class.java)

        fun fromStream(
            stream: ByteBuffer,
            isCopied: Boolean,
            optionClass: Ipv4OptionClassType,
            size: UByte,
        ): Ipv4OptionStrictSourceAndRecordRoute {
            logger.debug("SIZE: $size, remaining: ${stream.remaining()}")
            if (stream.remaining() < (size - 2u).toInt()) {
                throw PacketTooShortException(
                    "Stream must have at least ${size - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionLooseSourceAndRecordRoute, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val pointer = stream.get().toUByte()
            val dataLength = size.toInt() - MIN_OPTION_SIZE.toInt()
            val routingData = ByteArray(dataLength)
            stream.get(routingData)
            return Ipv4OptionStrictSourceAndRecordRoute(
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

        other as Ipv4OptionStrictSourceAndRecordRoute

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
