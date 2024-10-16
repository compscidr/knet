package com.jasonernst.knet.transport.tcp

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.BYTES_TO_DATA_OFFSET
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionNoOperation
import io.mockk.every
import io.mockk.spyk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.nio.ByteBuffer

class TcpTests {
    @Test fun encapsulationTest() {
        val tcpHeader = TcpHeader()
        val stream = ByteBuffer.wrap(tcpHeader.toByteArray())
        val parsedHeader = TcpHeader.fromStream(stream)
        assertEquals(tcpHeader, parsedHeader)
    }

    @Test fun tooShort() {
        val tcpHeader = TcpHeader()
        val stream = ByteBuffer.wrap(tcpHeader.toByteArray())
        stream.limit(1)
        // limit to so small that we can't even read the data offset
        assertThrows<PacketTooShortException> {
            TcpHeader.fromStream(stream)
        }

        stream.rewind()
        stream.limit(BYTES_TO_DATA_OFFSET + 2)
        assertThrows<PacketTooShortException> {
            TcpHeader.fromStream(stream)
        }
    }

    @Test fun badDataOffset() {
        val tcpOptions = arrayListOf(TcpOptionEndOfOptionList())
        val tcpHeader = spyk(TcpHeader(options = tcpOptions))
        every { tcpHeader.getDataOffset() } returns 1u
        assertThrows<IllegalArgumentException> { tcpHeader.toByteArray() }

        // too low on update dataoffset
        assertThrows<IllegalArgumentException> { tcpHeader.addOption(TcpOptionNoOperation()) }

        // to high on update data offset
        every { tcpHeader.getDataOffset() } returns 20u
        assertThrows<IllegalArgumentException> { tcpHeader.addOption(TcpOptionNoOperation()) }
    }

    @Test fun flagsTest() {
        val tcpHeader = TcpHeader()
        tcpHeader.setAck(true)
        tcpHeader.setCwr(true)
        tcpHeader.setEce(true)
        tcpHeader.setFin(true)
        tcpHeader.setPsh(true)
        tcpHeader.setRst(true)
        tcpHeader.setSyn(true)
        tcpHeader.setUrg(true)
        assertTrue(tcpHeader.isAck())
        assertTrue(tcpHeader.isCwr())
        assertTrue(tcpHeader.isEce())
        assertTrue(tcpHeader.isFin())
        assertTrue(tcpHeader.isPsh())
        assertTrue(tcpHeader.isRst())
        assertTrue(tcpHeader.isSyn())
        assertTrue(tcpHeader.isUrg())
        val stream = ByteBuffer.wrap(tcpHeader.toByteArray())
        val parsedHeader = TcpHeader.fromStream(stream)
        assertEquals(parsedHeader, tcpHeader)
    }

    @Test fun createAckPacketTest() {
        val tcpHeader = TcpHeader()
        val ipHeader = Ipv4Header(totalLength = (Ipv4Header.IP4_MIN_HEADER_LENGTH + tcpHeader.getHeaderLength()).toUShort())

        val ackPacket =
            TcpHeaderFactory.createAckPacket(
                ipHeader,
                tcpHeader,
                ackNumber = 0u,
                seqNumber = Ipv4Header.packetCounter.getAndIncrement().toUInt(),
            )
        assertTrue(ackPacket.nextHeaders is TcpHeader)
        val createdTcpHeader = ackPacket.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader.isAck())
    }

    @Test fun createFinPacketTest() {
        val tcpHeader = TcpHeader()
        val ipHeader = Ipv4Header(totalLength = (Ipv4Header.IP4_MIN_HEADER_LENGTH + tcpHeader.getHeaderLength()).toUShort())

        val finPacket =
            TcpHeaderFactory.createFinPacket(
                ipHeader,
                tcpHeader,
                ackNumber = 0u,
                seqNumber = Ipv4Header.packetCounter.getAndIncrement().toUInt(),
            )
        assertTrue(finPacket.nextHeaders is TcpHeader)
        val createdTcpHeader = finPacket.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader.isFin())
    }

    @Test fun createRstPacketTest() {
        // tcp header is not an ACK
        val tcpHeader = TcpHeader()
        val ipHeader = Ipv4Header(totalLength = (Ipv4Header.IP4_MIN_HEADER_LENGTH + tcpHeader.getHeaderLength()).toUShort())
        val rstPacket =
            TcpHeaderFactory.createRstPacket(
                ipHeader,
                tcpHeader,
            )
        assertTrue(rstPacket.nextHeaders is TcpHeader)
        val createdTcpHeader = rstPacket.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader.isRst())
        assertEquals(0u, createdTcpHeader.sequenceNumber)
        val expectedAck = tcpHeader.sequenceNumber + ipHeader.getPayloadLength().toUInt() - tcpHeader.getHeaderLength()
        assertEquals(expectedAck, createdTcpHeader.acknowledgementNumber)

        // tcp header is an ACK
        val tcpHeader2 = TcpHeader(ack = true, sequenceNumber = 56u, acknowledgementNumber = 24u)
        val ipHeader2 = Ipv6Header(payloadLength = tcpHeader2.getHeaderLength())
        val rstPacket2 =
            TcpHeaderFactory.createRstPacket(
                ipHeader2,
                tcpHeader2,
            )
        assertTrue(rstPacket2.nextHeaders is TcpHeader)
        val createdTcpHeader2 = rstPacket2.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader2.isRst())
        assertEquals(tcpHeader2.acknowledgementNumber, createdTcpHeader2.sequenceNumber)
        assertEquals(0u, createdTcpHeader2.acknowledgementNumber)
    }

    @Test fun createSynPacketTest() {
        val synPacket = TcpHeaderFactory.createSynPacket(InetAddress.getLocalHost(), InetAddress.getLocalHost(), 56u, 85u, 22u, 1500u)
        assertTrue(synPacket.nextHeaders is TcpHeader)
        val createdTcpHeader = synPacket.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader.isSyn())
        assertEquals(22u, createdTcpHeader.sequenceNumber)
        assertEquals(56u, createdTcpHeader.sourcePort.toUInt())
        assertEquals(85u, createdTcpHeader.destinationPort.toUInt())
    }

    @Test fun createSynAckPacket() {
        val synPacket = TcpHeaderFactory.createSynPacket(InetAddress.getLocalHost(), InetAddress.getLocalHost(), 56u, 85u, 22u, 1500u)
        val synAckPacket = TcpHeaderFactory.createSynAckPacket(synPacket.ipHeader, synPacket.nextHeaders as TcpHeader, 1500u)
        assertTrue(synAckPacket.nextHeaders is TcpHeader)
        val createdTcpHeader = synAckPacket.nextHeaders as TcpHeader
        assertTrue(createdTcpHeader.isSyn())
        assertTrue(createdTcpHeader.isAck())

        // the syn-ack packet should have the ack number set to the sequence number of the syn packet + 1
        assertEquals(23u, createdTcpHeader.acknowledgementNumber)

        // call with a non-syn packet
        val nonSynPacket = TcpHeader()
        assertThrows<IllegalArgumentException> {
            TcpHeaderFactory.createSynAckPacket(synPacket.ipHeader, nonSynPacket, 1500u)
        }
    }
}
