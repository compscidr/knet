package com.jasonernst.knet.transport.tcp

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.BYTES_TO_DATA_OFFSET
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionNoOperation
import io.mockk.every
import io.mockk.spyk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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

    @Test fun toStringWithSequenceAndAck() {
        val tcpHeader = TcpHeader(sequenceNumber = 1000u, acknowledgementNumber = 2000u)

        val headerString = tcpHeader.toString(startingSequenceNumber = 10u, startingAcknowledgement = 1500u)
        println(headerString)
        assertTrue(headerString.contains("sequenceNumber=990"))
        assertTrue(headerString.contains("acknowledgementNumber=500"))
    }
}
