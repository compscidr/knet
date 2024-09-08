package com.jasonernst.knet.transport.tcp

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IPType
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.options.TCPOption
import com.jasonernst.knet.transport.tcp.options.TCPOption.Companion.parseOptions
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.ceil
import kotlin.random.Random

data class TCPHeader(
    // 16-bits, source port
    override var sourcePort: UShort = Random.nextInt(UShort.MAX_VALUE.toInt()).toUShort(),
    // 16-bits, destination port
    override var destinationPort: UShort = Random.nextInt(UShort.MAX_VALUE.toInt()).toUShort(),
    // 32-bits, sequence number
    val sequenceNumber: UInt = 0U,
    // 32-bits, acknowledgement number (if ack set)
    var acknowledgementNumber: UInt = 0u,
    // indicates the header size + options size, in 32-bit words. This shares a byte with NS, so
    // updating either requires dataOffsetAndNs to be updated. the Offset should never be updated
    // directly - but should only be updated when the tcpOptions list changes.
    private var dataOffset: UByte = 5u,
    // flags. Updating these requires updating the flags byte
    private var cwr: Boolean = false,
    private var ece: Boolean = false,
    private var urg: Boolean = false,
    private var ack: Boolean = false,
    private var psh: Boolean = false,
    private var rst: Boolean = false,
    private var syn: Boolean = false,
    private var fin: Boolean = false,
    // 16-bits, windows size
    var windowSize: UShort = DEFAULT_WINDOW_SIZE,
    // 16-bits, checksum of the TCP header, IP pseudo-header and TCP data
    override var checksum: UShort = 0u,
    // 16-bits, urgent pointer (if urg set)
    var urgentPointer: UShort = 0u,
    // variable length depending on the options. Important that this remains private to force the
    // use of the add function which recalculates the data offset.
    private var options: List<TCPOption> = listOf(),
    override val protocol: UByte = IPType.TCP.value,
    override val typeString: String = "TCP",
) : TransportHeader {
    val logger = LoggerFactory.getLogger(javaClass)

    // 8-bits flags: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    var flags: UByte = 0u

    init {
        updateDataOffset()
        updateFlags()
    }

    companion object {
        // we may wish to change this, see this doc:
        // https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/description-tcp-features
        val DEFAULT_WINDOW_SIZE = 65535.toUShort()

        // https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/description-tcp-features
        val OFFSET_MIN: UByte = 5u // min because that's the minimum size of a TCP header
        val OFFSET_MAX: UByte = 15u // maximum because its a 4-bit field
        const val TCP_WORD_LENGTH: UByte = 4u

        // with no options
        val MIN_HEADER_LENGTH: UShort = (OFFSET_MIN * TCP_WORD_LENGTH).toUShort()

        fun fromStream(stream: ByteBuffer): TCPHeader {
            val start = stream.position()
            // ensure we have enough bytes to get to the data offset of the header
            if (stream.remaining() < (OFFSET_MIN * TCP_WORD_LENGTH).toInt()) {
                throw PacketTooShortException(
                    "Not enough bytes to parse TCP header, expected at least " +
                        "${OFFSET_MIN * TCP_WORD_LENGTH} but only ${stream.remaining()} available",
                )
            }

            val sourcePort = stream.short.toUShort()
            val destinationPort = stream.short.toUShort()
            val sequenceNumber = stream.int.toUInt()
            val acknowledgementNumber = stream.int.toUInt()
            val dataOffset = (stream.get().toInt() shr 4 and 0x0F).toUByte()
            val flags = stream.get()
            val windowSize = stream.short.toUShort()
            val checksum = stream.short.toUShort()
            val urgentPointer = stream.short.toUShort()

            // if we fail to parse the options, this will throw a PacketHeaderException
            val options = parseOptions(stream, start + (dataOffset * TCP_WORD_LENGTH).toInt())

            return TCPHeader(
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                sequenceNumber = sequenceNumber,
                acknowledgementNumber = acknowledgementNumber,
                dataOffset = dataOffset,
                cwr = flags.toInt() and 0x80 shr 7 == 1,
                ece = flags.toInt() and 0x40 shr 6 == 1,
                urg = flags.toInt() and 0x20 shr 5 == 1,
                ack = flags.toInt() and 0x10 shr 4 == 1,
                psh = flags.toInt() and 0x08 shr 3 == 1,
                rst = flags.toInt() and 0x04 shr 2 == 1,
                syn = flags.toInt() and 0x02 shr 1 == 1,
                fin = flags.toInt() and 0x01 shr 0 == 1,
                windowSize = windowSize,
                checksum = checksum,
                urgentPointer = urgentPointer,
                options = options,
            )
        }
    }

    /**
     * This is driven completely by the TCPOptions. If there are no options , the data offset should
     * be 5. If there are options, the data offset should be 5 + the number of 32-bit words the
     * options take up (zero padded). The NS bit has been removed from the original RFC793 standard
     * according to RFC 293, so we just need to make sure the offset is in the first four bytes and
     * that the second four bytes are zero padded.
     */
    private fun updateDataOffset() {
        var optionsLength = 0
        for (option in options) {
            optionsLength += option.size.toInt()
        }
        val octetLength = ceil(optionsLength.toDouble() / TCP_WORD_LENGTH.toDouble()).toUInt()
        dataOffset = (OFFSET_MIN + octetLength).toUByte()

        if (dataOffset < OFFSET_MIN || dataOffset > OFFSET_MAX) {
            throw IllegalArgumentException("dataOffset must be between 5 and 15 but is: $dataOffset")
        }
    }

    // should be called after any of the flags are updated
    private fun updateFlags() {
        flags = 0u
        flags =
            if (cwr) {
                flags or 0x80u
            } else {
                flags and 0x7Fu
            }
        flags =
            if (ece) {
                flags or 0x40u
            } else {
                flags and 0xBFu
            }
        flags =
            if (urg) {
                flags or 0x20u
            } else {
                flags and 0xDFu
            }
        flags =
            if (ack) {
                flags or 0x10u
            } else {
                flags and 0xEFu
            }
        flags =
            if (psh) {
                flags or 0x08u
            } else {
                flags and 0xF7u
            }
        flags =
            if (rst) {
                flags or 0x04u
            } else {
                flags and 0xFBu
            }
        flags =
            if (syn) {
                flags or 0x02u
            } else {
                flags and 0xFDu
            }
        flags =
            if (fin) {
                flags or 0x01u
            } else {
                flags and 0xFEu
            }
    }

    fun clearOptions() {
        options = listOf()
        updateDataOffset()
    }

    fun getOptions(): List<TCPOption> = options

    /**
     * Options must be added here in order to update the data offset.
     */
    fun addOption(option: TCPOption) {
        options = options + option
        updateDataOffset()
    }

    fun getDataOffset(): UByte = dataOffset

    /**
     * Sets the congestion window reduced flag.
     * https://en.wikipedia.org/wiki/Transmission_Control_Protocol#:~:text=CWR%20(1%20bit)%3A%20Congestion,value%20of%20the%20SYN%20flag.
     *
     * @param cwr true / false indiciating whether the flag is set
     */
    fun setCwr(cwr: Boolean) {
        this.cwr = cwr
        updateFlags()
    }

    fun isCwr(): Boolean = cwr

    /**
     * Sets the ECN-echo flag.
     * https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
     *
     * @param ece true / false indiciating whether the flag is set
     */
    fun setEce(ece: Boolean) {
        this.ece = ece
        updateFlags()
    }

    fun isEce(): Boolean = ece

    /**
     * Sets the Urgent flag.
     * http://www.firewall.cx/networking-topics/protocols/tcp/137-tcp-window-size-checksum.html#:~:text=The%20urgent%20pointer%20flag%20in,exactly%20the%20urgent%20data%20ends.&text=You%20may%20also%20be%20interested,used%20when%20attacking%20remote%20hosts.
     *
     * @param urg true / false indiciating whether the flag is set
     */
    fun setUrg(urg: Boolean) {
        this.urg = urg
        updateFlags()
    }

    fun isUrg(): Boolean = urg

    /**
     * Sets the acknowledgement flag.
     *
     * @param ack true / false indiciating whether the flag is set
     */
    fun setAck(ack: Boolean) {
        this.ack = ack
        updateFlags()
    }

    fun isAck(): Boolean = ack

    /**
     * Sets the push flag which causes data to be forwarded immediately instead of waiting for
     * additional data at the buffer.
     *
     * https://packetlife.net/blog/2011/mar/2/tcp-flags-psh-and-urg/
     *
     * @param psh true / false indiciating whether the flag is set
     */
    fun setPsh(psh: Boolean) {
        this.psh = psh
        updateFlags()
    }

    fun isPsh(): Boolean = psh

    /**
     * Sets the reset flag which resets the connection.
     *
     * @param rst true / false indiciating whether the flag is set
     */
    fun setRst(rst: Boolean) {
        this.rst = rst
        updateFlags()
    }

    fun isRst(): Boolean = rst

    /**
     * Sets the syn flag which is done at the start of a TCP connection during the three-way handshake.
     *
     * @param syn true / false indicating whether the flag is set
     */
    fun setSyn(syn: Boolean) {
        this.syn = syn
        updateFlags()
    }

    fun isSyn(): Boolean = syn

    /**
     * Sets the finished flag to terminate the TCP connection.
     *
     * @param fin true / false indicating whether the flag is set
     */
    fun setFin(fin: Boolean) {
        this.fin = fin
        updateFlags()
    }

    fun isFin(): Boolean = fin

    /**
     * Header length is the data offset field * the size of TCP words (4 bytes). This is the
     * length of the minimal TCP header (4 words) + the length of the options.
     */
    override fun getHeaderLength(): UShort = (dataOffset * TCP_WORD_LENGTH).toUShort()

    override fun toByteArray(order: ByteOrder): ByteArray {
        // logger.debug("TCP HEADER LENGTH: ${getHeaderLength()}")
        // MIN_HEADER_LENGTH
        val optionsLength = options.sumOf { it.size.toInt() }
        // logger.debug("TCP OPTIONS LENGTH: $optionsLength")
        if ((getHeaderLength() - MIN_HEADER_LENGTH).toInt() < optionsLength) {
            throw IllegalArgumentException("Header length is too short for options")
        }
        val buffer = ByteBuffer.allocate(getHeaderLength().toInt())
        buffer.order(order)
        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putInt(sequenceNumber.toInt())
        buffer.putInt(acknowledgementNumber.toInt())
        val shiftedOffset = (dataOffset.toInt() shl 4).toUByte()
        buffer.put(shiftedOffset.toByte())
        buffer.put(flags.toByte())
        buffer.putShort(windowSize.toShort())
        buffer.putShort(checksum.toShort())
        buffer.putShort(urgentPointer.toShort())
        for (option in options) {
            val optionBytes = option.toByteArray()
            // logger.debug("OPTION $option, bytes size: ${optionBytes.size}")
            buffer.put(optionBytes)
        }
        return buffer.array()
    }

    override fun toString(): String =
        "TcpHeader{" +
            "sourcePort=" + Integer.toUnsignedString(sourcePort.toInt() and 0xFFFF) +
            ", destinationPort=" + Integer.toUnsignedString(destinationPort.toInt() and 0xFFFF) +
            ", sequenceNumber=" + sequenceNumber +
            ", acknowledgementNumber=" + acknowledgementNumber +
            ", dataOffset=" + Integer.toUnsignedString(dataOffset.toInt()) +
            ", cwr=" + cwr +
            ", ece=" + ece +
            ", urg=" + urg +
            ", ack=" + ack +
            ", psh=" + psh +
            ", rst=" + rst +
            ", syn=" + syn +
            ", fin=" + fin +
            ", windowSize=" + Integer.toUnsignedString(windowSize.toInt() and 0xFFFF) +
            ", checksum=" + checksum +
            ", urgentPointer=" + Integer.toUnsignedString(urgentPointer.toInt() and 0xfff) +
            ", options=" + options +
            '}'
}
