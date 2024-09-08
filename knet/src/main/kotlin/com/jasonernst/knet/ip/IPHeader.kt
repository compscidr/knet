package com.jasonernst.knet.ip

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IPv4Header.Companion.IP4_MIN_HEADER_LENGTH
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Collects up the common things between IPv4 and IPv6 headers.
 */
interface IPHeader {
    companion object {
        private val logger = LoggerFactory.getLogger(IPHeader::class.java)
        const val IP4_VERSION: UByte = 4u
        const val IP6_VERSION: UByte = 6u

        fun fromStream(stream: ByteBuffer): IPHeader {
            val start = stream.position()
            if (stream.remaining() < 1) {
                throw PacketTooShortException("Packet too short to determine type")
            }
            // version is in the top four bits of the first byte, so we need to shift and zero out
            // the bottom four bits
            val versionByte = stream.get()
            stream.position(start)
            return when (val version = (versionByte.toInt() shr 4 and 0x0F).toUByte()) {
                IP4_VERSION -> {
                    logger.debug("IPv4 packet")
                    IPv4Header.fromStream(stream)
                }
                IP6_VERSION -> {
                    logger.debug("IPv6 packet")
                    IPv6Header.fromStream(stream)
                }
                else -> {
                    throw IllegalArgumentException("Unknown packet type: $version")
                }
            }
        }

        /**
         * Creates an IP header with no extension headers / options with the given payload size,
         * protocol and source and destination addresses.
         */
        fun createIPHeader(
            sourceAddress: InetAddress,
            destinationAddress: InetAddress,
            protocol: IPType,
            payloadSize: Int,
        ): IPHeader {
            require(sourceAddress.javaClass == destinationAddress.javaClass) {
                "Source ${sourceAddress::javaClass} and destination  ${destinationAddress::javaClass} addresses must be of the same type"
            }
            return when (sourceAddress) {
                is Inet4Address -> {
                    val totalLength = (IP4_MIN_HEADER_LENGTH + payloadSize.toUShort()).toUShort()
                    IPv4Header(
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = protocol.value,
                        totalLength = totalLength,
                    )
                }
                is Inet6Address -> {
                    IPv6Header(
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = protocol.value,
                        payloadLength = payloadSize.toUShort(),
                    )
                }
                else -> {
                    // we should never get here because there are only the above two classes
                    // however linting forces us to make this exhaustive. Its not easily
                    // possible to test this branch because we can't even make a dummy class
                    // that extends InetAddress to do so.
                    throw IllegalArgumentException("Unknown address type: ${sourceAddress.javaClass.name}")
                }
            }
        }
    }

    // ipv4 or ipv6
    val version: UByte

    // 8-bits, Next-layer protocol (TCP, UDP, ICMP, etc)
    // from this list: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    val protocol: UByte

    val sourceAddress: InetAddress
    val destinationAddress: InetAddress

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray

    // return the length of the IP header, in bytes
    fun getHeaderLength(): UShort

    // returns the length of the payload of the IP packet, not including the header
    fun getPayloadLength(): UShort

    // return the length of the IP packet, including the header and payload, in bytes
    fun getTotalLength(): UShort
}
