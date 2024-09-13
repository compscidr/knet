package com.jasonernst.knet.ip

import com.jasonernst.icmp_common.Checksum
import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpHeader.Companion.IP4_VERSION
import com.jasonernst.knet.ip.options.Ipv4Option
import com.jasonernst.knet.ip.options.Ipv4Option.Companion.parseOptions
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.or

/**
 * Internet Protocol Version 4 Header Implementation.
 */
data class Ipv4Header(
    // 4-bits, should always be IP4_VERSION for an ipv4 packet.
    override val version: UByte = IP4_VERSION,
    // 4-bits, header size. Offset to start of data. This value x IP4_WORD_LENGTH is the header
    // length. Increases when we add options.
    val ihl: UByte = (IP4_MIN_HEADER_LENGTH / IP4_WORD_LENGTH).toUByte(),
    // 6-bits, differentiated services code point.
    val dscp: UByte = 0u,
    // 2-bits, explicit congestion notification.
    val ecn: UByte = 0u,
    // 16-bits, IP packet, including the header
    private val totalLength: UShort = 0u,
    // 16-bits, groups fragments of a single IPv4 datagram.
    val id: UShort = 0u,
    // if the packet is marked as don't fragment and we can't fit it in a single packet, drop it.
    val dontFragment: Boolean = true,
    // indicates if this is the last fragment of a larger IPv4 packet.
    val lastFragment: Boolean = true,
    // 13-bits, offset of this fragment from the start of the original packet.
    val fragmentOffset: UShort = 0u,
    // 8-bits, maximum time (hops) the packet is allowed to exist in the internet system.
    // decremented each time the packet passes through a router.
    val ttl: UByte = 64u,
    // 8-bits, Next-layer protocol (TCP, UDP, ICMP, etc)
    // from this list: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    override val protocol: UByte = IpType.UDP.value,
    // 16-bits, one's complement of the one's complement sum of the entire header
    // (does not include the payload)
    // https://en.wikipedia.org/wiki/IPv4#Header_checksum
    var headerChecksum: UShort = 0u,
    // 32-bits, source address
    override val sourceAddress: InetAddress = Inet4Address.getLocalHost(),
    // 32-bits, destination address
    override val destinationAddress: InetAddress = Inet4Address.getLocalHost(),
    val options: List<Ipv4Option> = emptyList(),
) : IpHeader {
    // 3-bits: set from mayFragment and lastFragment
    // bit 0: Reserved; must be zero
    // bit 1: Don't Fragment (DF)
    // bit 2: More Fragments (MF)
    private var flag: Byte = 0

    init {
        if (dontFragment) {
            flag = flag or 0x40
        }
        if (lastFragment) {
            flag = flag or 0x20
        }

        // dummy check that ihl matches the options length
        val optionsLength = options.sumOf { it.size.toInt() }.toUInt()
        if (ihl * IP4_WORD_LENGTH != (IP4_MIN_HEADER_LENGTH + optionsLength).toUByte().toUInt()) {
            val expectedIHL = ((IP4_MIN_HEADER_LENGTH + optionsLength) / IP4_WORD_LENGTH).toUByte()
            throw IllegalArgumentException(
                "Invalid IPv4 header. IHL does not match the options length, IHL should be $expectedIHL, but was $ihl because options length was $optionsLength",
            )
        }

        // calculate the checksum for packet creation based on the set fields
        if (headerChecksum == 0u.toUShort()) {
            logger.debug("Calculating checksum for IPv4 header")
            val buffer = toByteArray()
            // ^ this will compute the checksum and put it in the buffer
            // note: it's tempting to call the checksum function here but if we do we'll get a zero
            // checksum because the field hasn't been zero'd out after the toByteArray call.
            headerChecksum = ByteBuffer.wrap(buffer).getShort(CHECKSUM_OFFSET).toUShort()
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(Ipv4Header::class.java)
        private const val CHECKSUM_OFFSET = 10
        const val IP4_WORD_LENGTH: UByte = 4u
        val IP4_MIN_HEADER_LENGTH: UByte = (IP4_WORD_LENGTH * 5u).toUByte()

        fun fromStream(stream: ByteBuffer): Ipv4Header {
            val start = stream.position()
            // logger.debug("Parsing IPv4 header from position: $start. remaining: ${stream.remaining()}, limit: ${stream.limit()}")

            // ensure we can get the version
            if (stream.remaining() < 1) {
                throw PacketTooShortException("IPv4Header: stream too short to determine version")
            }

            // ensure we have an IPv4 packet
            val versionAndHeaderLength = stream.get().toUByte()
            logger.debug("Version and Header Length: $versionAndHeaderLength")
            val ipVersion = (versionAndHeaderLength.toInt() shr 4 and 0x0F).toUByte()
            if (ipVersion != IP4_VERSION) {
                throw IllegalArgumentException("Invalid IPv4 header. IP version should be 4 but was $ipVersion")
            }

            // ensure we have enough capacity in the stream to parse out a full header
            val ihl: UByte = (versionAndHeaderLength.toInt() and 0x0F).toUByte()
            val headerAvailable = stream.limit() - start
            if (headerAvailable < (ihl * IP4_WORD_LENGTH).toInt()) {
                throw PacketTooShortException(
                    "Not enough space in stream for IPv4 header, expected ${ihl * 4u} but only have $headerAvailable",
                )
            }

            val dscpAndEcn = stream.get().toUByte()
            val dscp: UByte = (dscpAndEcn.toInt() shr 2 and 0x3F).toUByte()
            val ecn: UByte = (dscpAndEcn.toInt() and 0x03).toUByte()
            val totalLength = stream.short.toUShort()
            val id = stream.short.toUShort()
            val flagsAndFragmentOffset = stream.short.toUShort()
            val dontFragment = flagsAndFragmentOffset.toInt() and 0x4000 != 0
            val lastFragment = flagsAndFragmentOffset.toInt() and 0x2000 != 0
            val fragmentOffset: UShort = (flagsAndFragmentOffset.toInt() and 0x1FFF).toUShort()
            val ttl = stream.get().toUByte()
            val protocol = stream.get().toUByte()
            val checksum = stream.short.toUShort()

            val source = ByteArray(4)
            stream[source]
            val sourceAddress = Inet4Address.getByAddress(source) as Inet4Address
            val destination = ByteArray(4)
            stream[destination]
            val destinationAddress = Inet4Address.getByAddress(destination) as Inet4Address

            // make sure we don't process into a second packet
            val limitOfPacket = start + (ihl * IP4_WORD_LENGTH).toInt()
            val expectedRemaining = limitOfPacket - start - IP4_MIN_HEADER_LENGTH.toInt()
            if (stream.remaining() < expectedRemaining) {
                throw PacketTooShortException(
                    "Not enough data in stream to parse Ipv4 options, expecting $expectedRemaining, have ${stream.remaining()}",
                )
            }
            val options = parseOptions(stream, limitOfPacket)

            return Ipv4Header(
                ihl = ihl,
                dscp = dscp,
                ecn = ecn,
                totalLength = totalLength,
                id = id,
                dontFragment = dontFragment,
                lastFragment = lastFragment,
                fragmentOffset = fragmentOffset,
                ttl = ttl,
                protocol = protocol,
                headerChecksum = checksum,
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                options = options,
            )
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        // note: this will reserve the space that was previously setup for options
        // but they will be all zero'd out, not sure the impact of this
        val buffer = ByteBuffer.allocate((ihl * IP4_WORD_LENGTH).toInt())
        buffer.order(order)

        // combine version and ihl
        val versionIHL = ((IP4_VERSION.toInt() shl 4) + ihl.toInt()).toUByte()
        buffer.put(versionIHL.toByte())
        // combine dscp and ecn
        val dscpEcn = ((dscp.toInt() shl 2) + ecn.toInt()).toUByte()
        buffer.put(dscpEcn.toByte())
        buffer.putShort(totalLength.toShort())
        buffer.putShort(id.toShort())

        // combine flags + fragmentation
        val flagsFrags = ((flag.toInt() shl 8) + fragmentOffset.toInt()).toUShort()
        buffer.putShort(flagsFrags.toShort())
        buffer.put(ttl.toByte())
        buffer.put(protocol.toByte())
        buffer.putShort(0) // zero-out checksum
        buffer.put(sourceAddress.address)
        buffer.put(destinationAddress.address)
        for (option in options) {
            buffer.put(option.toByteArray())
        }
        buffer.rewind()

        // compute checksum and write over the zero value
        val ipChecksum = Checksum.calculateChecksum(buffer)
        buffer.putShort(CHECKSUM_OFFSET, ipChecksum.toShort())

        return buffer.array()
    }

    override fun getHeaderLength(): UShort = (ihl * IP4_WORD_LENGTH).toUShort()

    override fun getTotalLength(): UShort = totalLength

    override fun getPayloadLength(): UShort = (totalLength - getHeaderLength()).toUShort()

    override fun toString(): String =
        "IPv4Header(" +
            "version=$version" +
            ", ihl=$ihl" +
            ", dscp=$dscp" +
            ", ecn=$ecn" +
            ", totalLength=${Integer.toUnsignedString(totalLength.toInt())}" +
            ", id=${Integer.toUnsignedString(id.toInt())}" +
            ", dontFragment=$dontFragment" +
            ", lastFragment=$lastFragment" +
            ", fragmentOffset=$fragmentOffset" +
            ", ttl=$ttl" +
            ", protocol=$protocol" +
            ", headerChecksum=${Integer.toUnsignedString(headerChecksum.toInt())}" +
            ", sourceAddress=$sourceAddress, destinationAddress=$destinationAddress, flag=$flag)"
}
