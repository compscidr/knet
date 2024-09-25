package com.jasonernst.knet.ip.v6

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpHeader
import com.jasonernst.knet.ip.v6.extenions.Ipv6HopByHopOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class Ipv6HeaderTest {
    @Test
    fun tooShort() {
        val stream = ByteBuffer.allocate(0)
        assertThrows<PacketTooShortException> {
            Ipv6Header.fromStream(stream)
        }
    }

    @Test
    fun badVersion() {
        val stream = ByteBuffer.allocate(1)
        stream.put(0x00)
        stream.rewind()
        assertThrows<IllegalArgumentException> {
            Ipv6Header.fromStream(stream)
        }
    }

    @Test
    fun partialheader() {
        val stream = ByteBuffer.allocate(2)
        stream.put(0x60)
        stream.put(0x00)
        stream.rewind()
        assertThrows<PacketTooShortException> {
            Ipv6Header.fromStream(stream)
        }
    }

    @Test
    fun extensionHeaderTest() {
        val ipv6Header = Ipv6Header(extensionHeaders = listOf(Ipv6HopByHopOptions()))
        val stream = ByteBuffer.wrap(ipv6Header.toByteArray())
        val parsedHeader = IpHeader.fromStream(stream)
        assertEquals(ipv6Header, parsedHeader)
    }
}
