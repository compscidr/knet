package com.jasonernst.knet.transport.tcp.options

import com.jasonernst.knet.PacketTooShortException
import java.nio.ByteBuffer
import java.nio.ByteOrder

abstract class TcpOption(
    val type: TcpOptionTypeSupported,
    val size: UByte,
) {
    companion object {
        const val BASE_OPTION_SIZE = 2

        /**
         * Does not try to recover from a PacketHeaderException, or any other exception. The callee
         * should keep track of the start position and return the buffer to the starting position and
         * then skip over this packet using the data offset + the payload length to get to the next
         * packet if this fails.
         *
         * Note that because of the way padding works with options, you may find that you write a
         * TCP option list to buffer without a TCPEndOfOptionList and then try to parse it back and
         * find there is one - this is because the TCPEndOfOptionList is just zero padding. This is
         * expected and you need to consider this when designing tests which check for equality of
         * TCPHeaders.
         */
        fun parseOptions(
            stream: ByteBuffer,
            limit: Int,
        ): List<TcpOption> {
            val options = ArrayList<TcpOption>()
            while (stream.position() + 1 <= limit) {
                val kind = stream.get().toUByte()
                if (kind == TcpOptionTypeSupported.EndOfOptionList.kind) {
                    // end of options
                    // logger.debug("End of options")
                    options.add(TcpOptionEndOfOptionList)
                    break
                } else if (kind == TcpOptionTypeSupported.NoOperation.kind) {
                    // no operation
                    // logger.debug("No operation")
                    options.add(TcpOptionNoOperation)
                } else if (kind == TcpOptionTypeSupported.MaximumSegmentSize.kind) {
                    if (stream.remaining() < 3) {
                        throw PacketTooShortException(
                            "Expecting: 3 bytes, have: ${stream.remaining()} " +
                                "not enough bytes to parse TCP MSS option",
                        )
                    }
                    // logger.debug("Maximum segment size")
                    // skip over the length
                    stream.get()
                    val maxSegmentSize = stream.short.toUShort()
                    options.add(TcpOptionMaximumSegmentSize(mss = maxSegmentSize))
                } else if (kind == TcpOptionTypeSupported.Timestamps.kind) {
                    // logger.debug("Timestamps")
                    if (stream.remaining() < 9) {
                        throw PacketTooShortException(
                            "Expecting: 9 bytes, have: ${stream.remaining()} " +
                                "not enough bytes to parse TCP timestamp option",
                        )
                    }
                    // skip over the length
                    stream.get()
                    val tsval = stream.getInt().toUInt()
                    val tsecr = stream.getInt().toUInt()
                    options.add(TcpOptionTimestamp(tsval, tsecr))
//            } else if (kind == TCPOptionSACKPermitted.kind) {
//                // skip over length
//                BufferUtil.getUnsignedByte(stream).toByte()
//                options.add(TCPOptionSACKPermitted)
//            } else if (kind == TCPOptionSACK.kind) {
//                val length = BufferUtil.getUnsignedByte(stream).toByte()
//                if (length - 2 > stream.remaining()) {
//                    throw PacketTooShortException(
//                        "Expecting: $length bytes, have: ${stream.remaining()} not enough bytes " +
//                                "to parse TCP option",
//                    )
//                }
//                val data = ByteArray(length - 2)
//                stream.get(data)
//                // todo: properly parse these into the left and right edges of blocks
                } else {
                    // logger.debug("Unsupported option: $kind")
                    if (stream.remaining() < 1) {
                        throw PacketTooShortException(
                            "Expecting: 1 byte, have: ${stream.remaining()} not enough bytes to parse" +
                                " length of unsupported TCP option",
                        )
                    }
                    // unsupported option
                    val length = stream.get()
                    if (length - 2 > stream.remaining()) {
                        throw PacketTooShortException(
                            "Expecting: $length bytes, have: ${stream.remaining()} not enough bytes " +
                                "to parse TCP option",
                        )
                    }
                    val data = ByteArray(length - 2)
                    stream.get(data)
                    options.add(TcpOptionUnsupported(kind, data))
                }
            }
            stream.position(limit) // in case we have zero padding
            return options
        }
    }

    /**
     * Writes the kind and size into the array. Types which extend this should override this method,
     * call super.toByteArray() and then append their own data to the array.
     */
    open fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer =
            if (size > 1u) {
                ByteBuffer.allocate(BASE_OPTION_SIZE)
            } else {
                // handle the NOP case
                ByteBuffer.allocate(1)
            }
        buffer.order(order)
        buffer.put(type.kind.toByte())
        if (size > 1u) {
            // skip adding the size for NOP
            buffer.put(size.toByte())
        }
        return buffer.array()
    }
}
