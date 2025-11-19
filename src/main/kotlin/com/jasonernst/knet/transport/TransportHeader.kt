package com.jasonernst.knet.transport

import com.jasonernst.icmp.common.Checksum
import com.jasonernst.icmp.common.PacketHeaderException
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header.Companion.IP6_HEADER_SIZE
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

/**
 * Common functionality across Transport (TCP, UDP) headers
 */
interface TransportHeader : NextHeader {
    val sourcePort: UShort
    val destinationPort: UShort
    var checksum: UShort

    companion object {
        const val IP4_PSEUDO_HEADER_LENGTH = 12
    }

    /**
     * Compute the checksum for the header + payload. Note: this function does not set the checksum, it only returns
     * it. It is up to the caller to replace the checksum in the header with this computed version if they wish.
     *
     * @param ipHeader the IP header used in the checksum calculation
     * @param payload the payload used in the checksum calculation
     * @param verify - if true, the checksum will be verified against the checksum in the header
     * @param checksumWarn - if true, a warning will be logged if the checksum is incorrect rather
     *   than throwing an exception
     */
    fun computeChecksum(
        ipHeader: IpHeader,
        payload: ByteArray,
        verify: Boolean = false,
        checksumWarn: Boolean = false,
    ): UShort {
        val logger = LoggerFactory.getLogger(javaClass)
        val pseudoHeader: ByteBuffer
        if (ipHeader is Ipv4Header) {
            // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
            pseudoHeader = ByteBuffer.allocate(IP4_PSEUDO_HEADER_LENGTH + ipHeader.getPayloadLength().toInt())
            pseudoHeader.put(ipHeader.sourceAddress.address)
            pseudoHeader.put(ipHeader.destinationAddress.address)
            pseudoHeader.put(0)
            pseudoHeader.put(ipHeader.protocol.toByte())
            pseudoHeader.putShort(ipHeader.getPayloadLength().toShort())
        } else if (ipHeader is Ipv6Header) {
            val extensionHeaderLength = ipHeader.extensionHeaders.sumOf { it.getExtensionLengthInBytes() }
            val tcpLength = ipHeader.getPayloadLength().toInt() - extensionHeaderLength
            // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv6
            pseudoHeader = ByteBuffer.allocate(IP6_HEADER_SIZE.toInt() + tcpLength)
            pseudoHeader.put(ipHeader.sourceAddress.address)
            pseudoHeader.put(ipHeader.destinationAddress.address)
            pseudoHeader.putInt(tcpLength)
            val nextHeader = (ipHeader.extensionHeaders.lastOrNull()?.nextHeader ?: ipHeader.protocol).toInt()
            pseudoHeader.putInt(nextHeader)
        } else {
            throw IllegalArgumentException("Unknown IP header type")
        }
        val pseudoHeaderTransportStart = pseudoHeader.position()
        pseudoHeader.put(toByteArray())
        pseudoHeader.put(payload)

        // zero out the checksum field if it has already been set
        when (this) {
            is TcpHeader -> {
                pseudoHeader.putShort(pseudoHeaderTransportStart + TcpHeader.CHECKSUM_OFFSET.toInt(), 0)
            }

            is UdpHeader -> {
                pseudoHeader.putShort(pseudoHeaderTransportStart + UdpHeader.CHECKSUM_OFFSET.toInt(), 0)
            }

            else -> {
                throw IllegalArgumentException("Unknown transport header type")
            }
        }
        pseudoHeader.rewind()
        val computedChecksum = Checksum.calculateChecksum(pseudoHeader)

        if (verify) {
            val existingChecksum = this.checksum

            if (computedChecksum.toInt() != existingChecksum.toInt()) {
                if (checksumWarn) {
                    logger.warn("Checksum verification failed for ${javaClass.simpleName}: $computedChecksum != $existingChecksum")
                } else {
                    logger.error(
                        "Checksum verification failed for ${javaClass.simpleName}: $this $computedChecksum != $existingChecksum",
                    )
                    throw PacketHeaderException(
                        "Invalid ${javaClass.simpleName} checksum: $computedChecksum != $existingChecksum",
                    )
                }
            }
        }

        return computedChecksum
    }
}
