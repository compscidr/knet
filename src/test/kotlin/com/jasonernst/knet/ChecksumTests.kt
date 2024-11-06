package com.jasonernst.knet

import com.jasonernst.icmp.common.PacketHeaderException
import com.jasonernst.knet.datalink.EthernetHeader
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.packetdumper.filedumper.TextFilePacketDumper
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.io.FileNotFoundException
import kotlin.math.min
import org.junit.jupiter.api.Assertions.assertEquals

class ChecksumTests {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test fun ipv4TcpBadChecksum() {
        val filename = "/test_packets/ipv4_tcp_badchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is TcpHeader)
        val tcpHeader = nextHeader as TcpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - tcpHeader.getHeaderLength().toInt())
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        assertThrows<PacketHeaderException> {
            tcpHeader.computeChecksum(ipHeader, payload, true)
        }
    }

    @Test fun ipv4TcpGoodChecksum() {
        val filename = "/test_packets/ipv4_tcp_goodchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is TcpHeader)
        val tcpHeader = nextHeader as TcpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - tcpHeader.getHeaderLength().toInt())
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        tcpHeader.computeChecksum(ipHeader, payload, true)
    }

    @Test fun ipv4UdpBadChecksum() {
        val filename = "/test_packets/ipv4_udp_badchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is UdpHeader)
        val udpHeader = nextHeader as UdpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - udpHeader.getHeaderLength().toInt())
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        assertThrows<PacketHeaderException> {
            udpHeader.computeChecksum(ipHeader, payload, true)
        }
    }

    @Test fun ipv4UdpGoodChecksum() {
        val filename = "/test_packets/ipv4_udp_goodchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is UdpHeader)
        val udpHeader = nextHeader as UdpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - udpHeader.getHeaderLength().toInt())
        logger.debug("Payload length: {}", remainingPayloadSize)
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        val checksum = udpHeader.computeChecksum(ipHeader, payload, true)
        assertEquals(0xd9f0.toUShort(), checksum)
    }

    @Test fun ipv6TcpBadChecksum() {
        val filename = "/test_packets/ipv6_tcp_badchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        EthernetHeader.fromStream(stream)
        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is TcpHeader)
        val tcpHeader = nextHeader as TcpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - tcpHeader.getHeaderLength().toInt())
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        assertThrows<PacketHeaderException> {
            tcpHeader.computeChecksum(ipHeader, payload, true)
        }
    }

    @Test fun ipv6TcpGoodChecksum() {
        val filename = "/test_packets/ipv6_tcp_goodchecksum.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        EthernetHeader.fromStream(stream)
        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP Header: {}", ipHeader)
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TransportHeader)
        assertTrue(nextHeader is TcpHeader)
        val tcpHeader = nextHeader as TcpHeader

        // this may be a bad checksum because the length of the payload is truncated, so we'll
        // do a min check to prevent buffer underflow
        val remainingPayloadSize = min(stream.remaining(), ipHeader.getPayloadLength().toInt() - tcpHeader.getHeaderLength().toInt())
        val payload = ByteArray(remainingPayloadSize)
        stream.get(payload)

        tcpHeader.computeChecksum(ipHeader, payload, true)
    }

    /**
     * Regression test where the correct checksum was being computed but not returned.
     */
    @Test fun ensureTcpChecksumIsReturned() {
        val tcpHeader = TcpHeader()
        val ipHeader = Ipv6Header(payloadLength = tcpHeader.getHeaderLength())
        val checksum = tcpHeader.computeChecksum(ipHeader, ByteArray(0))
        assertNotEquals(0u, checksum.toUInt())
    }
}
