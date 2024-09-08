package com.jasonernst.knet.ip

import com.jasonernst.icmp_common.Checksum
import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IPHeader.Companion.IP4_VERSION
import com.jasonernst.knet.ip.IPv4Header.Companion.IP4_MIN_HEADER_LENGTH
import com.jasonernst.knet.ip.IPv4Header.Companion.IP4_WORD_LENGTH
import com.jasonernst.knet.transport.tcp.TCPHeader
import com.jasonernst.knet.transport.tcp.options.TCPOptionEndOfOptionList
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Mostly tests checksums
 */
class IPv4HeaderTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val stringPacketDumper = StringPacketDumper()

    private fun byteArrayOfInts(vararg ints: Int) =
        ByteArray(ints.size) { pos ->
            ints[pos].toByte()
        }

    private fun byteBufferOfInts(vararg ints: Int) = ByteBuffer.wrap(byteArrayOfInts(*ints))

    @Test
    fun ipv4checksumTest2() {
        val buffer =
            byteBufferOfInts(
                0x45,
                0x00,
                0x00,
                0x73,
                0x00,
                0x00,
                0x40,
                0x00,
                0x40,
                0x11,
                0xb8,
                0x61,
                0xc0,
                0xa8,
                0x00,
                0x01,
                0xc0,
                0xa8,
                0xc7,
            )
        val preChecksumDump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer pre-check clear: \n$preChecksumDump")
        buffer.putShort(10, 0) // clear checksum short
        val dump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer post-check clear: \n$dump")
        val checksum = Checksum.calculateChecksum(buffer)
        val expectedChecksum = 0xf227.toUShort()
        println("Expected: $expectedChecksum, Computed: $checksum")
        assert(checksum == expectedChecksum)
    }

    @Test
    fun ipv4checksumTest3() {
        val buffer =
            byteBufferOfInts(
                0x45,
                0x00,
                0x00,
                0x3c,
                0x00,
                0x00,
                0x00,
                0x00,
                0x40,
                0x06,
                0x21,
                0x75,
                0x8e,
                0xfa,
                0xbf,
                0x4e,
                0x0a,
                0x00,
                0x01,
                0x01,
            )
        buffer.putShort(10, 0) // clear checksum short
        val dump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer: \n$dump")
        val checksum = Checksum.calculateChecksum(buffer)
        val expectedChecksum = 0x2173.toUShort()
        println("Expected: $expectedChecksum, Computed: $checksum")
        assert(checksum == expectedChecksum)
    }

    @Test
    fun toBufferDontFragmentTest() {
        val source = InetAddress.getByName("127.0.0.1")
        val destination = InetAddress.getByName("8.8.8.8")
        // don't fragment = false
        val fragment =
            IPv4Header(
                version = IP4_VERSION,
                ihl = (IP4_MIN_HEADER_LENGTH / IP4_WORD_LENGTH).toUByte(),
                dscp = 0u,
                ecn = 0u,
                totalLength = IP4_MIN_HEADER_LENGTH.toUShort(),
                id = 0u,
                dontFragment = false,
                lastFragment = false,
                fragmentOffset = 0u,
                ttl = 64u,
                protocol = 0u,
                headerChecksum = 0u,
                sourceAddress = source,
                destinationAddress = destination,
            )
        var headerBytes = fragment.toByteArray()
        fragment.headerChecksum = ByteBuffer.wrap(headerBytes, 10, 2).short.toUShort()
        var buffer = ByteBuffer.wrap(fragment.toByteArray())
        var parsedHeader = IPHeader.fromStream(buffer)
        assertEquals(fragment, parsedHeader)

        // don't fragment = true
        val dontFragment =
            IPv4Header(
                version = IP4_VERSION,
                ihl = (IP4_MIN_HEADER_LENGTH / IP4_WORD_LENGTH).toUByte(),
                dscp = 0u,
                ecn = 0u,
                totalLength = IP4_MIN_HEADER_LENGTH.toUShort(),
                id = 0u,
                dontFragment = true,
                lastFragment = false,
                fragmentOffset = 0u,
                ttl = 64u,
                protocol = 0u,
                headerChecksum = 0u,
                sourceAddress = source,
                destinationAddress = destination,
            )

        headerBytes = dontFragment.toByteArray()
        dontFragment.headerChecksum = ByteBuffer.wrap(headerBytes, 10, 2).short.toUShort()
        buffer = ByteBuffer.wrap(dontFragment.toByteArray())
        parsedHeader = IPHeader.fromStream(buffer)
        assertEquals(dontFragment, parsedHeader)
    }

    @Test
    fun toFragmentOffsetTest() {
        val source = InetAddress.getByName("127.0.0.1")
        val destination = InetAddress.getByName("8.8.8.8")
        // don't fragment = false
        val ipv4header =
            IPv4Header(
                version = IP4_VERSION,
                ihl = (IP4_MIN_HEADER_LENGTH / IP4_WORD_LENGTH).toUByte(),
                dscp = 0u,
                ecn = 0u,
                totalLength = IP4_MIN_HEADER_LENGTH.toUShort(),
                id = 0u,
                dontFragment = true,
                lastFragment = false,
                fragmentOffset = 8191u,
                ttl = 64u,
                protocol = 0u,
                headerChecksum = 0u,
                sourceAddress = source,
                destinationAddress = destination,
            )
        val headerBytes = ipv4header.toByteArray()
        ipv4header.headerChecksum = ByteBuffer.wrap(headerBytes, 10, 2).short.toUShort()
        val buffer = ByteBuffer.wrap(ipv4header.toByteArray())
        val parsedHeader = IPHeader.fromStream(buffer)
        assertEquals(ipv4header, parsedHeader)
    }

    @Test
    fun toBufferDscpEcnTest() {
        val source = InetAddress.getByName("127.0.0.1")
        val destination = InetAddress.getByName("8.8.8.8")
        // don't fragment = false
        val ipv4header =
            IPv4Header(
                version = IP4_VERSION,
                ihl = (IP4_MIN_HEADER_LENGTH / IP4_WORD_LENGTH).toUByte(),
                dscp = 0b101010u,
                ecn = 0b10u,
                totalLength = IP4_MIN_HEADER_LENGTH.toUShort(),
                id = 0u,
                dontFragment = true,
                lastFragment = false,
                fragmentOffset = 8191u,
                ttl = 64u,
                protocol = 0u,
                headerChecksum = 0u,
                sourceAddress = source,
                destinationAddress = destination,
            )
        val headerBytes = ipv4header.toByteArray()
        ipv4header.headerChecksum = ByteBuffer.wrap(headerBytes, 10, 2).short.toUShort()
        val buffer = ByteBuffer.wrap(ipv4header.toByteArray())
        val parsedHeader = IPHeader.fromStream(buffer)
        assertEquals(ipv4header, parsedHeader)
    }

    @Test fun tcpIpMultiplePacketTest() {
        val source = InetAddress.getByName("127.0.0.1")
        val destination = InetAddress.getByName("8.8.8.8")
        val tcpHeader =
            TCPHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TCPOptionEndOfOptionList,
                    ),
            )
        val tcpHeader2 =
            TCPHeader(
                sourcePort = 3456u,
                destinationPort = 789u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TCPOptionEndOfOptionList,
                    ),
            )
        val ipHeader =
            IPHeader.createIPHeader(
                source,
                destination,
                IPType.TCP,
                tcpHeader.getHeaderLength().toInt(),
            )
        val ipHeader2 =
            IPHeader.createIPHeader(
                source,
                destination,
                IPType.UDP,
                tcpHeader2.getHeaderLength().toInt(),
            )

        val buffer =
            ByteBuffer.allocate(
                (
                    ipHeader.getHeaderLength() + tcpHeader.getHeaderLength() +
                        ipHeader2.getHeaderLength() + tcpHeader2.getHeaderLength()
                ).toInt(),
            )
        buffer.put(ipHeader.toByteArray())
        buffer.put(tcpHeader.toByteArray())
        buffer.put(ipHeader2.toByteArray())
        buffer.put(tcpHeader2.toByteArray())

        buffer.rewind()
        val dump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer: $dump")

        val parsedIpHeader = IPHeader.fromStream(buffer)
        val parsedTcpHeader = TCPHeader.fromStream(buffer)
        val parsedIpHeader2 = IPHeader.fromStream(buffer)
        val parsedTCPHeader2 = TCPHeader.fromStream(buffer)

        assertEquals(ipHeader, parsedIpHeader)
        assertEquals(tcpHeader, parsedTcpHeader)
        assertEquals(ipHeader2, parsedIpHeader2)
        assertEquals(tcpHeader2, parsedTCPHeader2)
    }

    @Test
    fun tooShortPacketTest() {
        val buffer = ByteBuffer.allocate(0)
        assertThrows<PacketTooShortException> {
            IPv4Header.fromStream(buffer)
        }
    }

    @Test
    fun badIPVersion() {
        val buffer = ByteBuffer.allocate(1)
        buffer.put(0x00)
        buffer.rewind()
        assertThrows<IllegalArgumentException> {
            IPv4Header.fromStream(buffer)
        }
    }

    @Test fun tooShortForFullHeader() {
        val buffer = ByteBuffer.allocate(2)
        buffer.put(0x45)
        buffer.put(0x00)
        buffer.rewind()
        assertThrows<PacketTooShortException> {
            IPv4Header.fromStream(buffer)
        }
    }

    // this is only a temp test until we properly implement ipv4 options
    @Test fun testOptionDropping() {
        val ipv4Packet = IPv4Header(ihl = 6u)
        logger.debug("IPv4 packet: {}", ipv4Packet)
        val buffer = ByteBuffer.wrap(ipv4Packet.toByteArray())
        val parsedPacket = IPHeader.fromStream(buffer)
        assertEquals(0u, buffer.remaining().toUInt())
        assertEquals(ipv4Packet, parsedPacket)
    }
}
