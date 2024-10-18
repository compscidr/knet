package com.jasonernst.knet.network.ip.v4

import com.jasonernst.icmp_common.Checksum
import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpHeader.Companion.IP4_VERSION
import com.jasonernst.knet.network.ip.IpHeader.Companion.closestDivisibleBy
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.options.Ipv4Option
import com.jasonernst.knet.network.ip.v4.options.Ipv4Option.Companion.parseOptions
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger
import kotlin.experimental.or
import kotlin.math.ceil
import kotlin.math.min

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
    // 16-bits, IP packet, including the header: default to a just the header with no payload
    private val totalLength: UShort = IP4_MIN_HEADER_LENGTH.toUShort(),
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
    override val sourceAddress: Inet4Address = Inet4Address.getLocalHost() as Inet4Address,
    // 32-bits, destination address
    override val destinationAddress: Inet4Address = Inet4Address.getLocalHost() as Inet4Address,
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
        val expectedIHL = ceil((IP4_MIN_HEADER_LENGTH.toDouble() + optionsLength.toDouble()) / IP4_WORD_LENGTH.toDouble()).toUInt()
        if (ihl.toUInt() != expectedIHL) {
            throw IllegalArgumentException(
                "Invalid IPv4 header. IHL does not match the options length, IHL should be $expectedIHL, but was $ihl because options length was $optionsLength",
            )
        }

        // calculate the checksum for packet creation based on the set fields
        if (headerChecksum == 0u.toUShort()) {
            val buffer = toByteArray()
            // ^ this will compute the checksum and put it in the buffer
            // note: it's tempting to call the checksum function here but if we do we'll get a zero
            // checksum because the field hasn't been zero'd out after the toByteArray call.
            headerChecksum = ByteBuffer.wrap(buffer).getShort(CHECKSUM_OFFSET).toUShort()
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(Ipv4Header::class.java)
        val packetCounter: AtomicInteger = AtomicInteger(0) // used to generate monotonic ids for Ipv4 packets
        private const val CHECKSUM_OFFSET = 10
        const val IP4_WORD_LENGTH: UByte = 4u
        val IP4_MIN_HEADER_LENGTH: UByte = (IP4_WORD_LENGTH * 5u).toUByte()
        val IP4_MIN_FRAGMENT_PAYLOAD: UByte = 8u // since they must be measured in 64-bit octets

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

        /**
         * To assemble the fragments of an internet datagram, an internet
         *     protocol module (for example at a destination host) combines
         *     internet datagrams that all have the same value for the four fields:
         *     identification, source, destination, and protocol.  The combination
         *     is done by placing the data portion of each fragment in the relative
         *     position indicated by the fragment offset in that fragment's
         *     internet header.  The first fragment will have the fragment offset
         *     zero, and the last fragment will have the more-fragments flag reset
         *     to zero.
         *
         *  NOTE: The fragment offset is measured in units of 8 octets (64 bits).  The
         *     first fragment has offset zero.
         *
         */
        fun reassemble(fragments: List<Pair<Ipv4Header, ByteArray>>): Pair<Ipv4Header, ByteArray> {
            if (fragments.isEmpty()) {
                throw IllegalArgumentException("Cannot reassemble an empty list of fragments")
            }
            if (fragments.size == 1) {
                if (fragments[0].first.lastFragment) {
                    return fragments[0]
                } else {
                    throw IllegalArgumentException("Cannot reassemble a single fragment that is not marked as the last fragment")
                }
            }
            val firstFragment = fragments[0]
            val totalPayloadLength = fragments.sumOf { it.first.totalLength - it.first.getHeaderLength() }
            logger.debug("TOTAL PAYLOAD LEN: $totalPayloadLength")
            val payload = ByteArray(totalPayloadLength.toInt())
            for (fragment in fragments) {
                if (fragment.first.id != firstFragment.first.id ||
                    fragment.first.protocol != firstFragment.first.protocol ||
                    fragment.first.sourceAddress != firstFragment.first.sourceAddress ||
                    fragment.first.destinationAddress != firstFragment.first.destinationAddress
                ) {
                    throw IllegalArgumentException("Trying to re-assemble packets which don't have matching id, protocol, src, dest")
                }
                val fragmentPayload = fragment.second
                val payloadPosition = fragment.first.fragmentOffset * 8u // measured in 64-bit octets
                fragmentPayload.copyInto(payload, payloadPosition.toInt())
            }
            return Pair(
                Ipv4Header(
                    ihl = firstFragment.first.ihl,
                    dscp = firstFragment.first.dscp,
                    ecn = firstFragment.first.ecn,
                    totalLength = (totalPayloadLength + firstFragment.first.getHeaderLength()).toUShort(),
                    id = firstFragment.first.id,
                    dontFragment = firstFragment.first.dontFragment,
                    lastFragment = true,
                    fragmentOffset = firstFragment.first.fragmentOffset,
                    ttl = firstFragment.first.ttl,
                    protocol = firstFragment.first.protocol,
                    sourceAddress = firstFragment.first.sourceAddress,
                    destinationAddress = firstFragment.first.destinationAddress,
                    options = firstFragment.first.options,
                ),
                payload,
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

    /**
     * Takes the current ipv4 header and fragments it into smaller ipv4 headers + payloads
     *
     * To fragment a long internet datagram, an internet protocol module
     *     (for example, in a gateway), creates two new internet datagrams and
     *     copies the contents of the internet header fields from the long
     *     datagram into both new internet headers.  The data of the long
     *     datagram is divided into two portions on a 8 octet (64 bit) boundary
     *     (the second portion might not be an integral multiple of 8 octets,
     *     but the first must be).  Call the number of 8 octet blocks in the
     *     first portion NFB (for Number of Fragment Blocks).  The first
     *     portion of the data is placed in the first new internet datagram,
     *     and the total length field is set to the length of the first
     *     datagram.  The more-fragments flag is set to one.  The second
     *     portion of the data is placed in the second new internet datagram,
     *     and the total length field is set to the length of the second
     *     datagram.  The more-fragments flag carries the same value as the
     *     long datagram.  The fragment offset field of the second new internet
     *     datagram is set to the value of that field in the long datagram plus
     *     NFB.
     *
     *     This procedure can be generalized for an n-way split, rather than
     *     the two-way split described.
     *
     *     When fragmentation occurs, some options are copied, but others
     *     remain with the first fragment only.
     *
     */
    fun fragment(
        maxSize: UInt, // max size includes the header size
        payload: ByteArray,
    ): List<Pair<Ipv4Header, ByteArray>> {
        if (maxSize.toInt() % 8 != 0) {
            throw IllegalArgumentException("Fragment max size must be divisible by 8")
        }
        if (dontFragment) {
            throw IllegalArgumentException("Cannot fragment packets marked as don't fragment")
        }
        val packetList = mutableListOf<Pair<Ipv4Header, ByteArray>>()
        // in order to fragment we need at least 1 byte of payload (which is why its <=)
        // this way we could make a large packet into a bunch of 1 byte payloads with headers if
        // we wanted
        if (maxSize < IP4_MIN_FRAGMENT_PAYLOAD) {
            throw IllegalArgumentException(
                "The smallest fragment size is ${IP4_MIN_FRAGMENT_PAYLOAD.toInt()} bytes because it must align on a 64-bit boundary",
            )
        }
        var lastFragment = false
        var payloadPosition = 0u
        var payloadPerPacket = min(payload.size - payloadPosition.toInt(), closestDivisibleBy(maxSize - getHeaderLength(), 8u).toInt())
        logger.debug("PAYLOAD PER PACKET: $payloadPerPacket HEADERSIZE: ${getHeaderLength()}")
        if (payloadPosition.toInt() + payloadPerPacket == payload.size) {
            lastFragment = true
        }

        var isFirstFragment = true
        while (payloadPosition < payload.size.toUInt()) {
            logger.debug("$payloadPosition:${payloadPosition + payloadPerPacket.toUInt()}")
            val offsetIn64BitOctets = payloadPosition / 8u
            var newOptions = options
            var newIhl = ihl

            if (isFirstFragment.not()) {
                newOptions = mutableListOf<Ipv4Option>()
                for (option in options) {
                    if (option.isCopied) {
                        newOptions.add(option)
                    }
                }
                val newOptionsLength = newOptions.sumOf { it.size.toInt() }.toUInt()
                newIhl =
                    ceil((IP4_MIN_HEADER_LENGTH.toDouble() + newOptionsLength.toDouble()) / IP4_WORD_LENGTH.toDouble()).toUInt().toUByte()
            } else {
                isFirstFragment = false
            }

            val newHeader =
                Ipv4Header(
                    ihl = newIhl,
                    dscp = dscp,
                    ecn = ecn,
                    totalLength = (getHeaderLength() + payloadPerPacket.toUInt()).toUShort(),
                    id = id,
                    dontFragment = false,
                    lastFragment = lastFragment,
                    fragmentOffset = offsetIn64BitOctets.toUShort(),
                    ttl = ttl,
                    protocol = protocol,
                    sourceAddress = sourceAddress,
                    destinationAddress = destinationAddress,
                    options = newOptions,
                )
            logger.debug("payload len:${newHeader.getPayloadLength()}")
            val newPayload = payload.copyOfRange(payloadPosition.toInt(), payloadPosition.toInt() + payloadPerPacket.toInt())
            packetList.add(Pair(newHeader, newPayload))
            payloadPosition += payloadPerPacket.toUInt()
            if (payloadPosition + payloadPerPacket.toUInt() > payload.size.toUInt()) {
                payloadPerPacket = (payload.size.toUInt() - payloadPosition).toInt()
                lastFragment = true
            }
        }
        return packetList
    }

    override fun getNextHeaderProtocol(): UByte = protocol
}
