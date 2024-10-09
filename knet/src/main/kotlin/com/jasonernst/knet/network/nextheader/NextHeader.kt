package com.jasonernst.knet.network.nextheader

import com.jasonernst.icmp_common.ICMPHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
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
            stream: ByteBuffer,
            protocol: UByte,
            limit: Int = stream.remaining(),
        ): NextHeader =
            when (protocol) {
                IpType.TCP.value -> {
                    TcpHeader.fromStream(stream)
                }

                IpType.UDP.value -> {
                    UdpHeader.fromStream(stream)
                }

                IpType.ICMP.value -> {
                    ICMPNextHeaderWrapper(
                        ICMPHeader.fromStream(buffer = stream, limit = limit),
                        protocol = IpType.ICMP.value,
                        typeString = "ICMP",
                    )
                }

                IpType.IPV6_ICMP.value -> {
                    ICMPNextHeaderWrapper(
                        ICMPHeader.fromStream(buffer = stream, limit = limit, isIcmpV4 = false),
                        protocol = IpType.IPV6_ICMP.value,
                        typeString = "ICMPv6",
                    )
                }

                else -> {
                    throw IllegalArgumentException("Unsupported protocol: $protocol")
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
