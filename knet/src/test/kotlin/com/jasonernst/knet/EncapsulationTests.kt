package com.jasonernst.knet

import com.jasonernst.knet.ip.IPHeader
import com.jasonernst.knet.ip.IPType
import com.jasonernst.knet.nextheader.NextHeader
import com.jasonernst.knet.transport.tcp.TCPHeader
import com.jasonernst.knet.transport.udp.UDPHeader
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import kotlin.random.Random

@Timeout(10)
class EncapsulationTests {
    private val logger = LoggerFactory.getLogger(javaClass)

    /**
     * General purpose helper so we can test various types of IP Headers, TransportHeaders, and
     * payloads without code duplication
     */
    private fun encapsulationTest(
        sourceAddress: InetSocketAddress,
        destinationAddress: InetSocketAddress,
        nextHeader: NextHeader,
        payload: ByteArray,
    ) {
        val protocol = IPType.fromValue(nextHeader.protocol)
        val ipPayloadSize = nextHeader.getHeaderLength().toInt() + payload.size
        val ipHeader = IPHeader.createIPHeader(sourceAddress.address, destinationAddress.address, protocol, ipPayloadSize)
        logger.debug("IP Header: {}", ipHeader)

        // compute checksums
//        if (transportHeader is UDPHeader) {
//            transportHeader.checksum = TransportHeaderFactoryImpl.computeChecksum(ipHeader, transportHeader, payload)
//        } else if (transportHeader is TCPHeader) {
//            transportHeader.checksum = TransportHeaderFactoryImpl.computeChecksum(ipHeader, transportHeader, payload)
//        }

        val stringPacketDumper = StringPacketDumper()
        val packet = Packet(ipHeader, nextHeader, payload)
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val streamHexDump = stringPacketDumper.dumpBufferToString(stream, 0, stream.limit())
        logger.debug("[TEST] STREAM:\n$streamHexDump")
        val parsedIpHeader = IPHeader.fromStream(stream)
        // output these so if it stops matching we can easily see why
        logger.debug("[TEST] IP HEADER: {}", ipHeader)
        logger.debug("[TEST] PARSED IP HEADER: {}", parsedIpHeader)
        assertEquals(ipHeader, parsedIpHeader)
        assertEquals(ipHeader.getPayloadLength().toInt(), stream.remaining())
        val parsedNextHeader = NextHeader.fromStream(stream, ipHeader.protocol)
        logger.debug("[TEST] NEXT HEADER: {}", nextHeader)
        logger.debug("[TEST] PARSED NEXT HEADER: {}", parsedNextHeader)
        assertEquals(nextHeader, parsedNextHeader)
        val parsedPayload = ByteBuffer.allocate((parsedIpHeader.getPayloadLength() - parsedNextHeader.getHeaderLength()).toInt())
        parsedPayload.put(stream)
        parsedPayload.flip()
        assertEquals(payload.contentToString(), parsedPayload.array().contentToString())
    }

    /**
     * Encapsulate and de-encapsulate test.
     * IPv4 and UDP
     *
     * Starts with a Packet -> writes to a buffer, parse the buffer back into a Packet and
     * assert everything matches.
     */
    @Test
    fun ipv4UdpEncapsulationTest() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("127.0.0.1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("8.8.8.8"), destPort)
        val udpHeader = UDPHeader(sourcePort.toUShort(), destPort.toUShort(), payload.size.toUShort(), 0u)
        encapsulationTest(sourceAddress, destinationAddress, udpHeader, payload)
    }

    /**
     * Encapsulate and de-encapsulate test.
     * IPv6 and UDP
     *
     * Starts with a Packet -> writes to a buffer, parse the buffer back into a Packet and
     * assert everything matches.
     */
    @Test
    fun ipv6UdpEncapsulationTest() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("::1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("::2"), destPort)
        val udpHeader = UDPHeader(sourcePort.toUShort(), destPort.toUShort(), payload.size.toUShort(), 0u)
        encapsulationTest(sourceAddress, destinationAddress, udpHeader, payload)
    }

    /**
     * Encapsulate and de-encapsulate test.
     * IPv4 and TCP
     *
     * Starts with a Packet -> writes to a buffer, parse the buffer back into a Packet and
     * assert everything matches.
     */
    @Test
    fun ipv4TcpEncapsulationTest() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("127.0.0.1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("8.8.8.8"), destPort)
        val tcpHeader =
            TCPHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        encapsulationTest(sourceAddress, destinationAddress, tcpHeader, payload)
    }

    /**
     * Encapsulate and de-encapsulate test.
     * IPv6 and TCP
     *
     * Starts with a Packet -> writes to a buffer, parse the buffer back into a Packet and
     * assert everything matches.
     */
    @Test
    fun ipv6TcpEncapsulationTest() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("::1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("::2"), destPort)
        val tcpHeader =
            TCPHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        encapsulationTest(sourceAddress, destinationAddress, tcpHeader, payload)
    }
}
