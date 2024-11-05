package com.jasonernst.knet

import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
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
        val protocol = IpType.fromValue(nextHeader.protocol)
        val ipPayloadSize = nextHeader.getHeaderLength().toInt() + payload.size
        val ipHeader = IpHeader.createIPHeader(sourceAddress.address, destinationAddress.address, protocol, ipPayloadSize)
        logger.debug("IP Header: {}", ipHeader)
        if (nextHeader is TransportHeader) {
            nextHeader.checksum = nextHeader.computeChecksum(ipHeader, payload)
        }
        val stringPacketDumper = StringPacketDumper()
        val packet = Packet(ipHeader, nextHeader, payload)
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val streamHexDump = stringPacketDumper.dumpBufferToString(stream, 0, stream.limit())
        logger.debug("[TEST] STREAM:\n$streamHexDump")
        val parsedIpHeader = IpHeader.fromStream(stream)
        // output these so if it stops matching we can easily see why
        logger.debug("[TEST] IP HEADER: {}", ipHeader)
        logger.debug("[TEST] PARSED IP HEADER: {}", parsedIpHeader)
        assertEquals(ipHeader, parsedIpHeader)
        assertEquals(ipHeader.getPayloadLength().toInt(), stream.remaining())
        val parsedNextHeader = NextHeader.fromStream(ipHeader, stream)
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
        val udpHeader = UdpHeader(sourcePort.toUShort(), destPort.toUShort(), payload.size.toUShort(), 0u)
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
        val udpHeader = UdpHeader(sourcePort.toUShort(), destPort.toUShort(), payload.size.toUShort(), 0u)
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
            TcpHeader(
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
            TcpHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        encapsulationTest(sourceAddress, destinationAddress, tcpHeader, payload)
    }

    @Test
    fun packetEncapsulationTest() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("::1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("::2"), destPort)
        val tcpHeader =
            TcpHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        val ipHeader =
            IpHeader.createIPHeader(
                sourceAddress.address,
                destinationAddress.address,
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt() + payload.size,
            )
        val packet = Packet(ipHeader, tcpHeader, payload)
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val parsedPacket = Packet.fromStream(stream)
        assertEquals(packet, parsedPacket)
    }

    @Test fun nonZeroChecksums() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("::1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("::2"), destPort)

        val tcpHeader =
            TcpHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        val ipHeader =
            IpHeader.createIPHeader(
                sourceAddress.address,
                destinationAddress.address,
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt() + payload.size,
            )
        val packet = Packet(ipHeader, tcpHeader, payload)
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val parsedPacket = Packet.fromStream(stream)
        assertNotEquals(0u, (parsedPacket.nextHeaders as TcpHeader).checksum)
        // edge case where we had extra left in the stream
        assertFalse(stream.hasRemaining())

        val udpHeader = UdpHeader(sourcePort.toUShort(), destPort.toUShort(), payload.size.toUShort(), 0u)
        val ipHeader2 =
            IpHeader.createIPHeader(
                sourceAddress.address,
                destinationAddress.address,
                IpType.UDP,
                udpHeader.getHeaderLength().toInt() + payload.size,
            )
        val packet2 = Packet(ipHeader2, udpHeader, payload)
        val stream2 = ByteBuffer.wrap(packet2.toByteArray())
        val parsedPacket2 = Packet.fromStream(stream2)
        assertNotEquals(0u, (parsedPacket2.nextHeaders as UdpHeader).checksum)
        // edge case where we had extra left in the stream
        assertFalse(stream2.hasRemaining())
    }
}
