package com.jasonernst.knet.transport.udp

import com.jasonernst.knet.PacketTooShortException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class UdpTests {
    @Test fun encapsulationTest() {
        val udpHeader = UdpHeader()
        val stream = ByteBuffer.wrap(udpHeader.toByteArray())
        val parsedHeader = UdpHeader.fromStream(stream)
        assertEquals(udpHeader, parsedHeader)
    }

    @Test fun tooShort() {
        val udpHeader = UdpHeader()
        val stream = ByteBuffer.wrap(udpHeader.toByteArray())
        stream.limit(stream.limit() - 5)
        assertThrows<PacketTooShortException> {
            UdpHeader.fromStream(stream)
        }
    }
}
