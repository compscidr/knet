package com.jasonernst.knet.transport.udp

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.TransportHeader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.random.Random

data class UdpHeader(
    // 16-bits, source port
    override var sourcePort: UShort = Random.nextInt(UShort.MAX_VALUE.toInt()).toUShort(),
    // 16-bits, destination port
    override var destinationPort: UShort = Random.nextInt(UShort.MAX_VALUE.toInt()).toUShort(),
    // 16-bits, length of the UDP header and UDP data, in bytes
    val totalLength: UShort = UDP_HEADER_LENGTH,
    // 16-bits, checksum of the UDP header, IP pseudo-header and UDP data
    override var checksum: UShort = 0u,
    override val protocol: UByte = IpType.UDP.value,
    override val typeString: String = "UDP",
) : TransportHeader {
    companion object {
        const val UDP_HEADER_LENGTH: UShort = 8u // udp header is not variable size unlike TCP
        const val CHECKSUM_OFFSET = 6u

        fun fromStream(stream: ByteBuffer): UdpHeader {
            // ensure we have enough capacity in the stream to parse out a full header
            if (stream.remaining() < UDP_HEADER_LENGTH.toInt()) {
                throw PacketTooShortException(
                    "Not enough space in stream for UDP header, expected $UDP_HEADER_LENGTH but only have ${stream.remaining()}",
                )
            }

            val sourcePort = stream.short.toUShort()
            val destinationPort = stream.short.toUShort()
            val length = stream.short.toUShort()
            val checksum = stream.short.toUShort()

            return UdpHeader(sourcePort = sourcePort, destinationPort = destinationPort, totalLength = length, checksum = checksum)
        }
    }

    override fun getHeaderLength(): UShort = UDP_HEADER_LENGTH

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(UDP_HEADER_LENGTH.toInt())
        buffer.order(order)
        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putShort(totalLength.toShort())
        buffer.putShort(checksum.toShort())
        return buffer.array()
    }
}
