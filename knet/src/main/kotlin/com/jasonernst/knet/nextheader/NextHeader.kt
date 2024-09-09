package com.jasonernst.knet.nextheader

import com.jasonernst.icmp_common.ICMPHeader
import com.jasonernst.knet.ip.IPType
import com.jasonernst.knet.transport.tcp.TCPHeader
import com.jasonernst.knet.transport.udp.UDPHeader
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
        ): NextHeader =
            when (protocol) {
                IPType.TCP.value -> {
                    TCPHeader.fromStream(stream)
                }

                IPType.UDP.value -> {
                    UDPHeader.fromStream(stream)
                }

                IPType.ICMP.value -> {
                    ICMPNextHeaderWrapper(ICMPHeader.fromStream(buffer = stream), protocol = IPType.ICMP.value, typeString = "ICMP")
                }

                IPType.IPV6_ICMP.value -> {
                    ICMPNextHeaderWrapper(ICMPHeader.fromStream(buffer = stream), protocol = IPType.IPV6_ICMP.value, typeString = "ICMPv6")
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
