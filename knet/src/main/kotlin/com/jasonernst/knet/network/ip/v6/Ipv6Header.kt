package com.jasonernst.knet.network.ip.v6

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpHeader.Companion.IP6_VERSION
import com.jasonernst.knet.network.ip.IpHeader.Companion.closestDivisibleBy
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6ExtensionHeader
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6Fragment
import com.jasonernst.knet.network.nextheader.NextHeader
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Represents an IPv6 header, including any extension headers.
 */
data class Ipv6Header(
    // 4-bits, should always be IP6_VERSION for an ipv6 packet.
    override val version: UByte = IP6_VERSION,
    // 8-bits: 6 MSB is differentiated service bits for packet classification, 2 LSB is ECN bits
    val trafficClass: UByte = 0u,
    // 20-bits: identify a flow between src and dest. flow = stream like TCP or media like RTP
    val flowLabel: UInt = 0u,
    // 16-bits: length of the payload, in bytes
    private val payloadLength: UShort = 0u,
    // 8-bits: next layer protocol number (TCP, UDP, ICMP, etc) in IPv6 often called NextHeader
    override val protocol: UByte = 0u,
    // 8-bits: hop limit, decremented by 1 at each hop, if 0, packet is discarded, similar to TTL
    val hopLimit: UByte = 0u,
    // 128-bits: source address
    override val sourceAddress: InetAddress = Inet6Address.getByName("::1"),
    // 128-bits: destination address
    override val destinationAddress: InetAddress = Inet6Address.getByName("::1"),
    val extensionHeaders: List<Ipv6ExtensionHeader> = emptyList(),
) : IpHeader {
    init {
        if (flowLabel > 0xFFFFFu) {
            // can't be more than 20 bits
            throw IllegalArgumentException("Flow label must be less than 0xFFFFF")
        }
    }

    companion object {
        private const val IP6_HEADER_SIZE: UShort = 40u // ipv6 header is not variable like ipv4

        // The Per-Fragment headers must consist of the IPv6 header plus any
        //      extension headers that must be processed by nodes en route to the
        //      destination, that is, all headers up to and including the Routing
        //      header if present
        private val onRouteHeaders =
            listOf(
                IpType.HOPOPT,
                IpType.IPV6_OPTS,
                IpType.IPV6_ROUTE,
            )

        fun fromStream(stream: ByteBuffer): Ipv6Header {
            val start = stream.position()

            // ensure we can get the version
            if (stream.remaining() < 1) {
                throw PacketTooShortException("IPv6Header: stream too short to determine version")
            }

            // ensure we have an IPv6 packet
            val versionAndHeaderLength = stream.get().toUByte()
            val ipVersion = (versionAndHeaderLength.toInt() shr 4 and 0x0F).toUByte()
            if (ipVersion != IP6_VERSION) {
                throw IllegalArgumentException("Invalid IPv6 header. IP version should be 6 but was $ipVersion")
            }

            // ensure we have enough capacity in the stream to parse out a full header
            val headerAvailable = stream.limit() - start
            if (headerAvailable < IP6_HEADER_SIZE.toInt()) {
                throw PacketTooShortException(
                    "Minimum Ipv6 header length is $IP6_HEADER_SIZE bytes. There are only $headerAvailable bytes available",
                )
            }

            // position back at start so we can get the traffic class
            stream.position(start)
            val versionUInt = stream.int.toUInt()
            val trafficClass = ((versionUInt and 0xFF00000u) shr 20).toUByte()
            val flowLabel = (versionUInt and 0xFFFFFu)
            val payloadLength = stream.short.toUShort()
            val protocol = stream.get().toUByte()
            val hopLimit = stream.get().toUByte()

            val sourceBuffer = ByteArray(16)
            stream[sourceBuffer]
            val sourceAddress = Inet6Address.getByAddress(sourceBuffer) as Inet6Address
            val destinationBuffer = ByteArray(16)
            stream[destinationBuffer]
            val destinationAddress = Inet6Address.getByAddress(destinationBuffer) as Inet6Address
            val extensionHeaders =
                Ipv6ExtensionHeader.fromStream(
                    stream,
                    IpType.fromValue(protocol),
                )

            return Ipv6Header(
                ipVersion,
                trafficClass,
                flowLabel,
                payloadLength,
                protocol,
                hopLimit,
                sourceAddress,
                destinationAddress,
                extensionHeaders,
            )
        }

        fun reassemble(fragments: List<Triple<Ipv6Header, NextHeader?, ByteArray>>): Triple<Ipv6Header, NextHeader, ByteArray> {
            if (fragments.isEmpty()) {
                throw IllegalArgumentException("No fragments to reassemble")
            }

            var firstFragmentHeader: Ipv6Fragment? = null
            val extensionHeaders = mutableListOf<Ipv6ExtensionHeader>()
            for (extensionHeader in fragments[0].first.extensionHeaders) {
                if (extensionHeader.type == IpType.IPV6_FRAG) {
                    firstFragmentHeader = extensionHeader as Ipv6Fragment
                    continue
                }
                extensionHeaders.add(extensionHeader)
            }
            if (firstFragmentHeader == null) {
                throw IllegalArgumentException("First fragment does not contain a fragment header")
            }
            val payloadLength =
                fragments.sumOf {
                    it.third.size
                } +
                    extensionHeaders.sumOf {
                        it.getExtensionLengthInBytes()
                    } + fragments[0].second!!.getHeaderLength().toInt()

            val ipv6Header =
                Ipv6Header(
                    version = fragments[0].first.version,
                    trafficClass = fragments[0].first.trafficClass,
                    flowLabel = fragments[0].first.flowLabel,
                    payloadLength = payloadLength.toUShort(),
                    protocol = fragments[0].first.protocol,
                    hopLimit = fragments[0].first.hopLimit,
                    sourceAddress = fragments[0].first.sourceAddress,
                    destinationAddress = fragments[0].first.destinationAddress,
                    extensionHeaders = extensionHeaders,
                )

            val nonHeaderPayloadLength = fragments.sumOf { it.third.size }
            val payload = ByteArray(nonHeaderPayloadLength)
            for (fragment in fragments) {
                val extensionHeaders = fragment.first.extensionHeaders
                var fragmentHeader: Ipv6Fragment? = null
                for (extensionHeader in extensionHeaders) {
                    if (extensionHeader.type == IpType.IPV6_FRAG) {
                        fragmentHeader = extensionHeader as Ipv6Fragment
                        break
                    }
                }
                if (fragmentHeader == null) {
                    throw IllegalArgumentException("Fragment does not contain a fragment header")
                }
                if (fragmentHeader.identification != firstFragmentHeader.identification) {
                    throw IllegalArgumentException("Fragment identification does not match first fragment")
                }
                val payloadPosition = fragmentHeader.fragmentOffset.toInt() * 8
                fragment.third.copyInto(payload, payloadPosition)
            }

            val nextHeader = fragments.first().second

            return Triple(ipv6Header, nextHeader!!, payload)
        }
    }

    /**
     * Fragments this ipv6 header into smaller fragments. The fragments have:
     * 1) an Ipv6 header with different sets of extension headers, depending on if its the first
     *    fragment or not
     * 2) a next header that is either the next header in the original packet or null if it is a
     *    fragment
     * 3) a payload that is a subset of the original payload
     */
    fun fragment(
        maxSize: UInt,
        nextHeader: NextHeader,
        payload: ByteArray,
    ): List<Triple<Ipv6Header, NextHeader?, ByteArray>> {
        if (maxSize.toInt() % 8 != 0) {
            throw IllegalArgumentException("Max size must be a multiple of 8")
        }

        val fragments = mutableListOf<Triple<Ipv6Header, NextHeader?, ByteArray>>()

        val perFragmentHeaders = mutableListOf<Ipv6ExtensionHeader>()

        // need to figure out type because this could be a mix of extension and upper layer headers (tcp)
        val nonPerFragmentExtensionHeaders = mutableListOf<Ipv6ExtensionHeader>()

        // up to an including the routing header if they exist
        for (extensionHeader in extensionHeaders) {
            if (onRouteHeaders.contains(extensionHeader.type)) {
                perFragmentHeaders.add(extensionHeader)
            } else {
                nonPerFragmentExtensionHeaders.add(extensionHeader)
            }
        }

        if (perFragmentHeaders.isNotEmpty()) {
            perFragmentHeaders.last().nextHeader = IpType.IPV6_FRAG.value
        }

        val perFragmentHeaderBytes =
            perFragmentHeaders.sumOf {
                it.getExtensionLengthInBytes()
            }
        val extAndUpperBytes =
            nonPerFragmentExtensionHeaders.sumOf {
                it.getExtensionLengthInBytes()
            } + nextHeader.getHeaderLength().toInt()

        val fragmentHeaderNextHeader =
            if (nonPerFragmentExtensionHeaders.isEmpty()) {
                nextHeader.protocol
            } else {
                nonPerFragmentExtensionHeaders.first().type.value
            }

        val firstFragmentHeader =
            Ipv6Fragment(
                nextHeader = fragmentHeaderNextHeader,
                fragmentOffset = 0u,
                moreFlag = true,
                identification = Ipv6Fragment.globalIdentificationCounter++,
            )

        val firstHeaderExtensions = mutableListOf<Ipv6ExtensionHeader>()
        firstHeaderExtensions.addAll(perFragmentHeaders)
        firstHeaderExtensions.add(firstFragmentHeader)
        firstHeaderExtensions.addAll(nonPerFragmentExtensionHeaders)

        val firstFragment =
            Ipv6Header(
                version,
                trafficClass,
                flowLabel,
                (maxSize - IP6_HEADER_SIZE).toUShort(),
                if (nonPerFragmentExtensionHeaders.isEmpty()) {
                    protocol
                } else {
                    IpType.IPV6_FRAG.value
                },
                hopLimit,
                sourceAddress,
                destinationAddress,
                firstHeaderExtensions,
            )
        val firstPayloadBytes =
            closestDivisibleBy(maxSize - IP6_HEADER_SIZE - perFragmentHeaderBytes.toUInt() - extAndUpperBytes.toUInt(), 8u)
        val minPayloadBytes = minOf(firstPayloadBytes, payload.size.toUInt())
        val firstPair = Triple(firstFragment, nextHeader, payload.sliceArray(0 until minPayloadBytes.toInt()))
        fragments.add(firstPair)
        var payloadPosition = minPayloadBytes.toInt()

        while (payloadPosition < payload.size) {
            val nextPayloadBytes =
                minOf(
                    (payload.size - payloadPosition).toUInt(),
                    maxSize - IP6_HEADER_SIZE - perFragmentHeaderBytes.toUInt(),
                )
            val moreFlag = nextPayloadBytes >= maxSize - IP6_HEADER_SIZE - perFragmentHeaderBytes.toUInt()

            val nextFragment =
                Ipv6Fragment(
                    nextHeader = fragmentHeaderNextHeader,
                    fragmentOffset = (payloadPosition / 8).toUShort(),
                    moreFlag = moreFlag,
                    identification = firstFragmentHeader.identification,
                )

            val nextHeaderExtensions = mutableListOf<Ipv6ExtensionHeader>()
            nextHeaderExtensions.addAll(perFragmentHeaders)
            nextHeaderExtensions.add(nextFragment)

            val nextFragmentHeader =
                Ipv6Header(
                    version,
                    trafficClass,
                    flowLabel,
                    (maxSize - IP6_HEADER_SIZE).toUShort(),
                    if (nonPerFragmentExtensionHeaders.isEmpty()) {
                        protocol
                    } else {
                        IpType.IPV6_FRAG.value
                    },
                    hopLimit,
                    sourceAddress,
                    destinationAddress,
                    nextHeaderExtensions,
                )

            val nextPair =
                Triple(
                    nextFragmentHeader,
                    null,
                    payload.sliceArray(
                        payloadPosition until (payloadPosition + nextPayloadBytes.toInt()),
                    ),
                )
            fragments.add(nextPair)
            payloadPosition += nextPayloadBytes.toInt()
        }

        return fragments
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val headerBytes = getHeaderLength()
        val buffer: ByteBuffer = ByteBuffer.allocate(headerBytes.toInt())
        buffer.order(order)

        // combine version, traffic class, flowlabel into a single int
        val versionUInt = (IP6_VERSION.toUInt() shl 28) + (trafficClass.toUInt() shl 20) + flowLabel
        buffer.putInt(versionUInt.toInt())
        buffer.putShort(payloadLength.toShort())
        buffer.put(protocol.toByte())
        buffer.put(hopLimit.toByte())
        buffer.put(sourceAddress.address)
        buffer.put(destinationAddress.address)

        for (extensionHeader in extensionHeaders) {
            buffer.put(extensionHeader.toByteArray())
        }
        return buffer.array()
    }

    override fun getHeaderLength(): UShort {
        val extensionHeadersLength =
            extensionHeaders.sumOf {
                it.getExtensionLengthInBytes()
            }
        return (IP6_HEADER_SIZE.toInt() + extensionHeadersLength).toUShort()
    }

    override fun getTotalLength(): UShort = (getHeaderLength() + payloadLength).toUShort()

    override fun getPayloadLength(): UShort = payloadLength

    override fun toString(): String {
        val extensionHeaderString = extensionHeaders.joinToString(", ", "[", "]")
        val string =
            "IPv6Header(version=$version, trafficClass=$trafficClass, flowLabel=$flowLabel, " +
                "payloadLength=$payloadLength, protocol=$protocol, hopLimit=$hopLimit, " +
                "sourceAddress=$sourceAddress, destinationAddress=$destinationAddress, " +
                "extensionHeaders=$extensionHeaderString)"
        return string
    }
}
