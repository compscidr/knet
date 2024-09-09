package com.jasonernst.knet.ip

import com.jasonernst.knet.PacketTooShortException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class IPv6HeaderTest {
    @Test
    fun tooShort() {
        val stream = ByteBuffer.allocate(0)
        assertThrows<PacketTooShortException> {
            IPv6Header.fromStream(stream)
        }
    }

    @Test
    fun badVersion() {
        val stream = ByteBuffer.allocate(1)
        stream.put(0x00)
        stream.rewind()
        assertThrows<IllegalArgumentException> {
            IPv6Header.fromStream(stream)
        }
    }

    @Test
    fun partialheader() {
        val stream = ByteBuffer.allocate(2)
        stream.put(0x60)
        stream.put(0x00)
        stream.rewind()
        assertThrows<PacketTooShortException> {
            IPv6Header.fromStream(stream)
        }
    }

    @Test
    fun extensionHeaderTest() {
        val ipv6Header = IPv6Header(extensionHeaders = listOf(IPv6HopByHopOption()))
        val stream = ByteBuffer.wrap(ipv6Header.toByteArray())
        val parsedHeader = IPHeader.fromStream(stream)
        assertEquals(ipv6Header, parsedHeader)
    }
}
