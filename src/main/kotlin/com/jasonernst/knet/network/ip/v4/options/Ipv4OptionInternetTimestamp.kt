package com.jasonernst.knet.network.ip.v4.options

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The Option Length is the number of octets in the option counting
 * the type, length, pointer, and overflow/flag octets (maximum
 * length 40).
 *
 * The Pointer is the number of octets from the beginning of this
 * option to the end of timestamps plus one (i.e., it points to the
 * octet beginning the space for next timestamp).  The smallest
 * legal value is 5.  The timestamp area is full when the pointer
 * is greater than the length.
 *
 * The Overflow (oflw) [4 bits] is the number of IP modules that
 * cannot register timestamps due to lack of space.
 *
 * The Flag (flg) [4 bits] values are
 *
 * 0 -- time stamps only, stored in consecutive 32-bit words,
 *
 * 1 -- each timestamp is preceded with internet address of the
 * registering entity,
 *
 * 3 -- the internet address fields are prespecified.  An IP
 * module only registers its timestamp if it matches its own
 * address with the next specified internet address.
 *
 * The Timestamp is a right-justified, 32-bit timestamp in
 * milliseconds since midnight UT.  If the time is not available in
 * milliseconds or cannot be provided with respect to midnight UT
 * then any time may be inserted as a timestamp provided the high
 * order bit of the timestamp field is set to one to indicate the
 * use of a non-standard value.
 *
 * The originating host must compose this option with a large
 * enough timestamp data area to hold all the timestamp information
 * expected.  The size of the option does not change due to adding
 * timestamps.  The intitial contents of the timestamp data area
 * must be zero or internet address/zero pairs.
 *
 * If the timestamp data area is already full (the pointer exceeds
 * the length) the datagram is forwarded without inserting the
 * timestamp, but the overflow count is incremented by one.
 *
 * If there is some room but not enough room for a full timestamp
 * to be inserted, or the overflow count itself overflows, the
 * original datagram is considered to be in error and is discarded.
 * In either case an ICMP parameter problem message may be sent to
 * the source host [3].
 *
 * The timestamp option is not copied upon fragmentation.  It is
 * carried in the first fragment.  Appears at most once in a
 * datagram.
 */
data class Ipv4OptionInternetTimestamp(
    override val isCopied: Boolean = false,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.DebuggingAndMeasurement,
    override val type: Ipv4OptionType = Ipv4OptionType.TimeStamp,
    val pointer: UByte,
    val overFlowFlags: UByte,
    val internetAddress: UInt,
    val timestamps: List<UInt>,
) : Ipv4Option(
        isCopied = isCopied,
        optionClass = optionClass,
        type = type,
        size = (MIN_OPTION_SIZE.toInt() + timestamps.size * 4).toUByte(),
    ) {
    companion object {
        private val logger = LoggerFactory.getLogger(Ipv4OptionInternetTimestamp::class.java)
        val MIN_OPTION_SIZE: UByte = 8u // 2 for type, size, 1 for pointer, 1 for overflow/flags, 4 for internet address

        fun fromStream(
            stream: ByteBuffer,
            isCopied: Boolean,
            optionClass: Ipv4OptionClassType,
            size: UByte,
        ): Ipv4OptionInternetTimestamp {
            logger.debug("SIZE: $size, remaining: ${stream.remaining()}")
            if (stream.remaining() < (size - 2u).toInt()) {
                throw PacketTooShortException(
                    "Stream must have at least ${size - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionInternetTimestamp, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val pointer = stream.get().toUByte()
            val overFlowFlags = stream.get().toUByte()
            val internetAddress = stream.int
            val timestamps = ArrayList<UInt>()
            while (stream.remaining() >= 4) {
                timestamps.add(stream.int.toUInt())
            }
            return Ipv4OptionInternetTimestamp(
                isCopied = isCopied,
                optionClass = optionClass,
                pointer = pointer,
                overFlowFlags = overFlowFlags,
                internetAddress = internetAddress.toUInt(),
                timestamps = timestamps,
            )
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer =
            ByteBuffer
                .allocate(MIN_OPTION_SIZE.toInt() + timestamps.size * 4)
                .order(order)
                .put(super.toByteArray(order))
                .put(pointer.toByte())
                .put(overFlowFlags.toByte())
                .putInt(internetAddress.toInt())
        timestamps.forEach { buffer.putInt(it.toInt()) }
        return buffer.array()
    }
}
