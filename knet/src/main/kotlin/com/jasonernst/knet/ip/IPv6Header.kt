package com.jasonernst.knet.ip

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IPHeader.Companion.IP6_VERSION
import org.slf4j.LoggerFactory
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Represents an IPv6 header, including any extension headers.
 */
data class IPv6Header(
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
    override val sourceAddress: InetAddress,
    // 128-bits: destination address
    override val destinationAddress: InetAddress,
    val extensionHeaders: List<IPv6ExtensionHeader> = emptyList(),
): IPHeader {
    companion object {
        private val logger = LoggerFactory.getLogger(IPv6Header::class.java)
        private const val IP6_HEADER_SIZE: UShort = 40u // ipv6 header is not variable like ipv4

        fun fromStream(stream: ByteBuffer): IPv6Header {
            val start = stream.position()

            // ensure we can get the version
            if (stream.remaining() < 1) {
                throw PacketTooShortException("IPv6Header: stream too short to determine version")
            }

            // ensure we have an IPv6 packet
            val versionAndHeaderLength = stream.get().toUByte()
            val ipVersion = (versionAndHeaderLength.toInt() shr 4 and 0x0F).toUByte()
            if (ipVersion != IPHeader.IP6_VERSION) {
                throw IllegalArgumentException("Invalid IPv6 header. IP version should be 6 but was $ipVersion")
            }

            // ensure we have enough capacity in the stream to parse out a full header
            val headerAvailable = stream.limit() - stream.position()
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

            // TODO: parse extension headers
//            val hopByHopOption =
//                if (protocol == IPType.HOPOPT.value) {
//                    IPv6HopByHopOption.fromStream(stream)
//                } else {
//                    null
//                }

            return IPv6Header(
                ipVersion,
                trafficClass,
                flowLabel,
                payloadLength,
                protocol,
                hopLimit,
                sourceAddress,
                destinationAddress,
                emptyList(), // todo properly parse this
            )
        }
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
        return (IP6_HEADER_SIZE + (extensionHeaders.sumOf { it.length.toInt() }).toUShort()).toUShort()
    }

    override fun getTotalLength(): UShort {
        return (getHeaderLength() + payloadLength).toUShort()
    }

    override fun getPayloadLength(): UShort {
        return payloadLength
    }

    override fun toString(): String {
        return "IPv6Header(version=$version, trafficClass=$trafficClass, flowLabel=$flowLabel, " +
                "payloadLength=$payloadLength, protocol=$protocol, hopLimit=$hopLimit, " +
                "sourceAddress=$sourceAddress, destinationAddress=$destinationAddress)"
    }
}