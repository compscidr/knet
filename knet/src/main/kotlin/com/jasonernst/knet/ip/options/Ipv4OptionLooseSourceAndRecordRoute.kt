package com.jasonernst.knet.ip.options

import com.jasonernst.knet.PacketTooShortException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * From RFC 791:
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
class Ipv4OptionLooseSourceAndRecordRoute(
    override val isCopied: Boolean = true,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.LooseSourceRouting,
    override val size: UByte = MIN_OPTION_SIZE,
    val pointer: UByte,
    val routeData: ByteArray = ByteArray(0),
) : Ipv4Option(isCopied, optionClass, type, size) {
    companion object {
        val MIN_OPTION_SIZE: UByte = 3u

        fun fromStream(
            stream: ByteBuffer,
            dataLength: Int,
        ): Ipv4OptionLooseSourceAndRecordRoute {
            if (stream.remaining() < MIN_OPTION_SIZE.toInt() - 2) {
                throw PacketTooShortException(
                    "Stream must have at least ${MIN_OPTION_SIZE - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionLooseSourceAndRecordRoute, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val pointer = stream.get().toUByte()
            val routingData = ByteArray(dataLength)
            stream.get(routingData)
            return Ipv4OptionLooseSourceAndRecordRoute(
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
}
