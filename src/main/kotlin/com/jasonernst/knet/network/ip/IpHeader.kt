package com.jasonernst.knet.network.ip

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.IP4_MIN_HEADER_LENGTH
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Collects up the common things between IPv4 and IPv6 headers.
 */
interface IpHeader {
    companion object {
        private val logger = LoggerFactory.getLogger(IpHeader::class.java)
        private val stringPacketDumper = StringPacketDumper(logger)
        const val IP4_VERSION: UByte = 4u
        const val IP6_VERSION: UByte = 6u

        /**
         * Helper function so that we can ensure the payload length is a multiple of 8
         */
        fun closestDivisibleBy(
            initialValue: UInt,
            divisor: UInt,
        ): UInt = (initialValue + divisor - 1u) / divisor * divisor

        fun fromStream(stream: ByteBuffer): IpHeader {
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
                    Ipv4Header.fromStream(stream)
                }
                IP6_VERSION -> {
                    Ipv6Header.fromStream(stream)
                }
                else -> {
                    // rewind the stream so we can dump what got us here
                    stream.position(start)
                    // dump the buffer without addresses, and without a dummy header, just purely
                    // the raw buffer that caused the problem
                    stringPacketDumper.dumpBuffer(stream, addresses = false, etherType = null)
                    // advance past where we were so we can try again
                    stream.position(stream.position() + 1)
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
            protocol: IpType,
            payloadSize: Int,
        ): IpHeader {
            require(sourceAddress.javaClass == destinationAddress.javaClass) {
                "Source ${sourceAddress::javaClass} and destination  ${destinationAddress::javaClass} addresses must be of the same type"
            }
            return when (sourceAddress) {
                is Inet4Address -> {
                    destinationAddress as Inet4Address
                    val totalLength = (IP4_MIN_HEADER_LENGTH + payloadSize.toUShort()).toUShort()
                    Ipv4Header(
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = protocol.value,
                        totalLength = totalLength,
                    )
                }
                is Inet6Address -> {
                    destinationAddress as Inet6Address
                    Ipv6Header(
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

    // 8-bits, Next-layer protocol (TCP, UDP, ICMP, etc) on Ipv4. On Ipv6, this can be the protocol
    // of the next extension header, or the next layer protocol if there are no more extension headers
    // from this list: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    val protocol: UByte

    // on IPv4, this is the same as above, but on IPv6, this is the next header from the last
    // extension header
    fun getNextHeaderProtocol(): UByte

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
