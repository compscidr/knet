package com.jasonernst.knet.network.nextheader

import com.jasonernst.icmp.common.v4.IcmpV4Header
import com.jasonernst.icmp.common.v6.IcmpV6Header
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Common functionality across headers that are encapsulated within an IP packet:
 * - TCP
 * - UDP
 * - ICMPv4
 * - ICMPv6
 */
interface NextHeader {
    companion object {
        fun fromStream(
            ipHeader: IpHeader,
            stream: ByteBuffer,
            limit: Int = stream.remaining(),
        ): NextHeader =
            when (ipHeader.getNextHeaderProtocol()) {
                IpType.TCP.value -> {
                    TcpHeader.fromStream(stream)
                }

                IpType.UDP.value -> {
                    UdpHeader.fromStream(stream)
                }

                IpType.ICMP.value -> {
                    ICMPNextHeaderWrapper(
                        IcmpV4Header.fromStream(buffer = stream, limit = limit),
                        protocol = IpType.ICMP.value,
                        typeString = "ICMP",
                    )
                }

                IpType.IPV6_ICMP.value -> {
                    ICMPNextHeaderWrapper(
                        IcmpV6Header.fromStream(
                            ipHeader.sourceAddress as Inet6Address,
                            ipHeader.destinationAddress as Inet6Address,
                            buffer = stream,
                            limit = limit,
                        ),
                        protocol = IpType.IPV6_ICMP.value,
                        typeString = "ICMPv6",
                    )
                }

                else -> {
                    throw IllegalArgumentException("Unsupported protocol: ${ipHeader.getNextHeaderProtocol()}")
                }
            }
    }

    // return the length of the header, in bytes (not including any payload it might have)
    fun getHeaderLength(): UShort

    // return the header as a byte array (not including any payload it might have)
    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray

    // Should match the value in the IP header protocol field
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    val protocol: UByte

    // Makes it easier to identify the type of header when debugging
    val typeString: String
}
