package com.jasonernst.knet.ip

import com.jasonernst.knet.PacketTooShortException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
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
        val ipv6Header = Ipv6Header(extensionHeaders = listOf(Ipv6HopByHopOption()))
        val stream = ByteBuffer.wrap(ipv6Header.toByteArray())
        val parsedHeader = IpHeader.fromStream(stream)
        assertEquals(ipv6Header, parsedHeader)
    }

    @Test
    fun hopByHopHashCode() {
        val map: MutableMap<Ipv6HopByHopOption, Int> = mutableMapOf()
        val ipv6HopByHopOption = Ipv6HopByHopOption()
        map[ipv6HopByHopOption] = 1
        assertTrue(map.containsKey(ipv6HopByHopOption))
    }

    @Test
    fun notEquals() {
        val ipv6HopByHopOption = Ipv6HopByHopOption()
        val otherOption = Ipv6ExtensionHeader(0u, 0u, ByteArray(0))
        assertFalse(ipv6HopByHopOption == otherOption)

        val ipv6HopByHopOption2 = Ipv6HopByHopOption(nextHeader = 0u)
        assertFalse(ipv6HopByHopOption == ipv6HopByHopOption2)

        val ipv6HopByHopOption3 = Ipv6HopByHopOption(length = 5u)
        assertFalse(ipv6HopByHopOption == ipv6HopByHopOption3)

        val ipv6HopByHopOption4 = Ipv6HopByHopOption(data = ByteArray(1))
        assertFalse(ipv6HopByHopOption == ipv6HopByHopOption4)
    }
}
