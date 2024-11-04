package com.jasonernst.knet.application.dns

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.properties.Delegates

/**
 * Implements the DNS QName format. Note that odd length names are allowed. There is no padding.
 *
 * https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
 */
data class DnsQName(
    private var name: String,
) {
    private var length by Delegates.notNull<UByte>()

    companion object {
        private val logger = LoggerFactory.getLogger(DnsQName::class.java)

        /**
         * Given a stream of bytes, parse the list of labels in the form of DNSQName(s) from the stream.
         * After calling this function, the stream will be positioned after the QNAME section of the
         * message.
         *
         * @param stream the stream of bytes to parse
         * @return a list of DnsQName(s) parsed from the stream
         */
        fun fromStream(
            stream: ByteBuffer,
            start: UShort,
        ): List<DnsQName> {
            val labels = ArrayList<DnsQName>()
            do {
                if (stream.remaining() < 1) {
                    throw PacketTooShortException(
                        "Not enough bytes to determine DNSQName length, need at least 1, have ${stream.remaining()}",
                    )
                }
                var length = stream.get().toUByte()

                // test if we have a pointer: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
                if ((length.toUInt() shr 6) and 0x3u == 0x3u) {
                    // if we have a pointer, we actually need two bytes for offset
                    stream.position(stream.position() - 1)
                    val offset = stream.short.toUShort() and 0x3FFFu
                    logger.debug("Got a label pointer: ${offset.toInt()}")
                    labels.addAll(fromStreamWithOffset(stream, start, offset))
                    break // a sequence of labels is ended with a pointer, so after we get a pointer we're done
                } else if (length.toUInt() and 0x3Fu == 0u) {
                    // we've reached the end of the sequence of labels
                    break
                } else {
                    length = length and 0x3Fu
                    logger.debug("Got a label of length ${length.toInt()}")
                    val nameBytes = ByteArray(length.toInt())
                    stream.get(nameBytes)
                    labels.add(DnsQName(String(nameBytes)))
                }
            } while (stream.hasRemaining())

            return labels
        }

        /**
         * Returns a list of QNames from the given stream with the supplied offset from the start of
         * the stream as a pointer. Returns the stream to the position it was in before this call.
         * @param the stream to to parse the offset from
         * @param offset the offset to parse the QNames from
         * @return a List of QName labels
         */
        private fun fromStreamWithOffset(
            stream: ByteBuffer,
            start: UShort,
            offset: UShort,
        ): List<DnsQName> {
            val originalPosition = stream.position()
            stream.position((start + offset).toInt())
            logger.debug("Parsing QNames from offset ${offset.toInt()} starting at: ${stream.position()}")
            val labels = fromStream(stream, start)
            stream.position(originalPosition)
            return labels
        }
    }

    init {
        setName(name)
    }

    fun setName(name: String) {
        if (name.length > (UByte.MAX_VALUE - 1u).toInt()) {
            throw IllegalArgumentException("QName length must be less than ${UByte.MAX_VALUE - 1u}")
        }
        this.name = name
        length = name.length.toUByte()
    }

    fun getName(): String = name

    fun getLength(): UShort {
        // extra 1 is because the actual name is preceded by the length byte
        return (length + 1u).toUShort()
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(length.toInt() + 1)
        buffer.order(order)
        buffer.put(length.toByte())

        // probably should use an encode function, but this will do for now
        buffer.put(name.toByteArray())

        return buffer.array()
    }
}
