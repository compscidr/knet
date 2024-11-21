package com.jasonernst.knet.network.icmp

import com.jasonernst.icmp.common.IcmpType
import com.jasonernst.icmp.common.PacketHeaderException
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket.Companion.DESTINATION_UNREACHABLE_HEADER_MIN_LENGTH
import com.jasonernst.icmp.common.v4.IcmpV4EchoPacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6EchoPacket
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.IP4_MIN_HEADER_LENGTH
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header.Companion.IP6_HEADER_SIZE
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.math.min

object IcmpFactory {
    private val logger = LoggerFactory.getLogger(javaClass)

    /**
     * Given an original packet, creates a destination unreachable packet originating at the sourceAddress. This
     * is useful for applications like proxies or VPNs where the destination is unreachable for some reason.
     *
     * According to this:
     * https://www.firewall.cx/networking-topics/protocols/icmp-protocol/153-icmp-destination-unreachable.html
     * and wireshark dumps, we must send back the IP header, the transport header, and payload of
     * the packet which generated the Icmp host unreachable.
     *
     * @param sourceAddress source address for the Icmp header
     * @param ipHeader the IP header of the packet which caused the host unreachable
     * @param transportHeader the transport header of the packet which caused the host unreachable
     *  (only the first 64-bits of it are used)
     *
     */
    fun createDestinationUnreachable(
        code: IcmpType,
        sourceAddress: InetAddress,
        packet: Packet,
        mtu: Int,
    ): Packet {
        val protocol =
            when (packet.ipHeader) {
                is Ipv4Header -> IpType.ICMP
                is Ipv6Header -> IpType.IPV6_ICMP
                else -> {
                    val className = if (packet.ipHeader == null) "null" else packet.ipHeader::class.toString()
                    throw PacketHeaderException("Unknown IP header type: $className")
                }
            }

        val originalTransportBufferAndPayloadBuffer = ByteBuffer.allocate(packet.ipHeader.getPayloadLength().toInt())
        originalTransportBufferAndPayloadBuffer.put(packet.nextHeaders?.toByteArray())
        originalTransportBufferAndPayloadBuffer.put(packet.payload)

        val limit =
            if (packet.ipHeader is Ipv4Header) {
                // rfc792 says to include the first 64-bits of the transport header, however, in practice, it seems
                // to follow similar rules to IPv6, so we'll include as much as possible without going over the min MTU
                // (verified with wireshark pcap dumps from my system)
                (mtu.toUInt() - IP4_MIN_HEADER_LENGTH - DESTINATION_UNREACHABLE_HEADER_MIN_LENGTH - packet.ipHeader.getHeaderLength())
                    .toInt()
            } else {
                // rfc4443 says to include as much as possible without going over the min MTU
                // IPv6 header length, ICMPv6 destination unreachable min header length, IPv6 header length (the one that generated this to happen)
                (mtu.toUInt() - IP6_HEADER_SIZE - DESTINATION_UNREACHABLE_HEADER_MIN_LENGTH - IP6_HEADER_SIZE).toInt()
            }
        val actualLimit = min(limit, originalTransportBufferAndPayloadBuffer.limit())
        val reducedTransportBuffer = ByteArray(actualLimit)
        System.arraycopy(originalTransportBufferAndPayloadBuffer.array(), 0, reducedTransportBuffer, 0, actualLimit)

        val modifiedOriginalRequestBuffer = ByteBuffer.allocate(packet.ipHeader.getHeaderLength().toInt() + actualLimit)
        modifiedOriginalRequestBuffer.put(packet.ipHeader.toByteArray())
        modifiedOriginalRequestBuffer.put(reducedTransportBuffer)
        modifiedOriginalRequestBuffer.rewind()

        val icmpHeader =
            when (packet.ipHeader) {
                is Ipv4Header -> {
                    IcmpV4DestinationUnreachablePacket(code as IcmpV4DestinationUnreachableCodes, 0u, modifiedOriginalRequestBuffer.array())
                }
                is Ipv6Header -> {
                    IcmpV6DestinationUnreachablePacket(
                        sourceAddress as Inet6Address,
                        packet.ipHeader.sourceAddress,
                        code as IcmpV6DestinationUnreachableCodes,
                        0u,
                        modifiedOriginalRequestBuffer.array(),
                    )
                }
                else -> {
                    throw PacketHeaderException("Unknown IP header type: ${packet.ipHeader::class}")
                }
            }
        val responseIpHeader =
            IpHeader.createIPHeader(
                sourceAddress,
                packet.ipHeader.sourceAddress,
                protocol,
                icmpHeader.size(),
            )

        return Packet(responseIpHeader, IcmpNextHeaderWrapper(icmpHeader, protocol.value, "Icmp"), ByteArray(0))
    }

    /**
     * Creates an ICMP echo packet.
     *
     * @param isReply whether the packet is a request or a reply
     * @param sequence the sequence number of the packet
     * @param identifier the identifier of the packet
     * @param sourceAddress the source address of the packet
     * @param destinationAddress the destination address of the packet
     * @return the ICMP echo packet
     */
    fun createIcmpEcho(
        isReply: Boolean,
        sequence: UShort,
        identifier: UShort,
        sourceAddress: InetAddress,
        destinationAddress: InetAddress,
        packet: Packet?,
    ): Packet {
        val protocol =
            if (sourceAddress is Inet4Address) {
                IpType.ICMP
            } else {
                IpType.IPV6_ICMP
            }

        val icmpHeader =
            when (sourceAddress) {
                is Inet4Address -> {
                    IcmpV4EchoPacket(0u, sequence, identifier, isReply, packet?.toByteArray() ?: ByteArray(0))
                }
                is Inet6Address -> {
                    IcmpV6EchoPacket(
                        sourceAddress,
                        destinationAddress as Inet6Address,
                        0u,
                        identifier,
                        sequence,
                        isReply,
                        packet?.toByteArray() ?: ByteArray(0),
                    )
                }
                else -> {
                    throw PacketHeaderException("Unknown IP header type: ${sourceAddress::class}")
                }
            }

        val ipHeader = IpHeader.createIPHeader(sourceAddress, destinationAddress, protocol, icmpHeader.size())
        return Packet(ipHeader, IcmpNextHeaderWrapper(icmpHeader, protocol.value, "Icmp"), ByteArray(0))
    }
}
