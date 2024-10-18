package com.jasonernst.knet.network.ip.v4

import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpHeader.Companion.closestDivisibleBy
import com.jasonernst.knet.network.ip.IpHeaderTest
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.IP4_MIN_HEADER_LENGTH
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.IP4_WORD_LENGTH
import com.jasonernst.knet.network.ip.v4.options.Ipv4OptionEndOfOptionList
import com.jasonernst.knet.network.ip.v4.options.Ipv4OptionNoOperation
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.nio.ByteBuffer
import kotlin.math.ceil

class Ipv4FragmentTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test
    fun fragmentationAndReassembly() {
        val payload =
            IpHeaderTest.Companion.byteArrayOfInts(
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
            )
        val ipv4Header = Ipv4Header(totalLength = (IP4_MIN_HEADER_LENGTH + payload.size.toUShort()).toUShort(), dontFragment = false)
        val fragmentSize = closestDivisibleBy(IP4_MIN_HEADER_LENGTH + (payload.size / 2).toUInt(), 8u)
        val fragments = ipv4Header.fragment(fragmentSize, payload)
        assertEquals(2, fragments.size)

        val reassembly = Ipv4Header.reassemble(fragments)
        assertEquals(ipv4Header, reassembly.first)
        assertArrayEquals(payload, reassembly.second)
    }

    @Test
    fun emptyFragments() {
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(emptyList())
        }
    }

    @Test
    fun singleFragmentWithoutLastFragmentSetToTrue() {
        val ipv4Header = Ipv4Header(lastFragment = false)
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(listOf(Pair(ipv4Header, ByteArray(0))))
        }
    }

    @Test
    fun singleFragmentLastFragment() {
        val payload = IpHeaderTest.Companion.byteArrayOfInts(0x01, 0x02, 0x03)
        val ipv4Header = Ipv4Header(totalLength = (IP4_MIN_HEADER_LENGTH + payload.size.toUInt()).toUShort(), dontFragment = false)
        val fragmentSize = closestDivisibleBy(IP4_MIN_HEADER_LENGTH + 8u, 8u)
        val fragmented = ipv4Header.fragment(fragmentSize, payload)
        val reassembled = Ipv4Header.reassemble(fragmented)
        assertEquals(ipv4Header, reassembled.first)
    }

    @Test
    fun notDivisbleBy8() {
        val ipv4Header = Ipv4Header()
        assertThrows<IllegalArgumentException> {
            ipv4Header.fragment(1u, ByteArray(0))
        }
    }

    @Test
    fun nonMatchingFragmentFields() {
        val ipv4Header = Ipv4Header(id = 1u)
        val ipv4Header2 = Ipv4Header(id = 2u)
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(listOf(Pair(ipv4Header, ByteArray(0)), Pair(ipv4Header2, ByteArray(0))))
        }

        val ipv4Header3 = Ipv4Header(id = 1u, protocol = IpType.TCP.value)
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(listOf(Pair(ipv4Header, ByteArray(0)), Pair(ipv4Header3, ByteArray(0))))
        }

        val ipv4Header4 = Ipv4Header(id = 1u, sourceAddress = Inet4Address.getByName("127.0.0.1") as Inet4Address)
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(listOf(Pair(ipv4Header, ByteArray(0)), Pair(ipv4Header4, ByteArray(0))))
        }

        val ipv4Header5 = Ipv4Header(id = 1u, destinationAddress = Inet4Address.getByName("127.0.0.1") as Inet4Address)
        assertThrows<IllegalArgumentException> {
            Ipv4Header.reassemble(listOf(Pair(ipv4Header, ByteArray(0)), Pair(ipv4Header5, ByteArray(0))))
        }
    }

    @Test
    fun fragmentADontFragment() {
        val ipv4Header = Ipv4Header(dontFragment = true)
        assertThrows<IllegalArgumentException> {
            ipv4Header.fragment(8u, IpHeaderTest.Companion.byteArrayOfInts(0x01, 0x02, 0x03))
        }
    }

    @Test
    fun fragmentTooSmall() {
        val ipv4Header = Ipv4Header(dontFragment = false)
        assertThrows<IllegalArgumentException> {
            ipv4Header.fragment(0u, IpHeaderTest.Companion.byteArrayOfInts(0x01, 0x02, 0x03))
        }
    }

    @Test
    fun fragmentWithOptions() {
        val options = listOf(Ipv4OptionNoOperation(isCopied = true), Ipv4OptionEndOfOptionList(isCopied = false))
        val optionsLength = options.sumOf { it.size.toInt() }
        val payload = ByteArray(16)
        val totalHeaderLength = (IP4_MIN_HEADER_LENGTH + optionsLength.toUInt())
        val ihl = ceil(totalHeaderLength.toDouble() / IP4_WORD_LENGTH.toDouble()).toUInt().toUByte()
        val totalLength = (((ihl * IP4_WORD_LENGTH) + payload.size.toUInt()).toUShort()) // account for zero padding the header
        val ipv4Header = Ipv4Header(ihl = ihl, totalLength = totalLength, dontFragment = false, options = options)
        val maxSize = closestDivisibleBy(totalHeaderLength + 8u, 8u)
        val fragments = ipv4Header.fragment(maxSize, payload)
        assertEquals(2, fragments.size)

        val reassembly = Ipv4Header.reassemble(fragments)
        assertEquals(ipv4Header, reassembly.first)
        assertArrayEquals(payload, reassembly.second)
    }

    /**
     * Prevent regression on flags being wrong
     */
    @Test
    fun testFlags() {
        // don't fragment, more fragments
        val ipv4Header1 = Ipv4Header(dontFragment = true, lastFragment = false)
        val dontFragmentMoreFragments = ipv4Header1.toByteArray()
        assertEquals(0x60u, dontFragmentMoreFragments[6].toUInt())
        val parsedHeader1 = Ipv4Header.fromStream(ByteBuffer.wrap(dontFragmentMoreFragments))
        assertEquals(ipv4Header1, parsedHeader1)

        // don't fragment, no more fragments (default)
        val ipv4Header2 = Ipv4Header(dontFragment = true, lastFragment = true)
        val dontFragmentNoMoreFragments = ipv4Header2.toByteArray()
        assertEquals(0x40u, dontFragmentNoMoreFragments[6].toUInt())
        val parsedHeader2 = Ipv4Header.fromStream(ByteBuffer.wrap(dontFragmentNoMoreFragments))
        assertEquals(ipv4Header2, parsedHeader2)

        val default = Ipv4Header().toByteArray()
        assertEquals(0x40u, default[6].toUInt())

        // do fragment, more fragments
        val ipv4Header3 = Ipv4Header(dontFragment = false, lastFragment = false)
        val doFragmentMoreFragments = ipv4Header3.toByteArray()
        assertEquals(0x20u, doFragmentMoreFragments[6].toUInt())
        val parsedHeader3 = Ipv4Header.fromStream(ByteBuffer.wrap(doFragmentMoreFragments))
        assertEquals(ipv4Header3, parsedHeader3)

        // do fragment, no more fragments
        val ipv4Header4 = Ipv4Header(dontFragment = false, lastFragment = true)
        val doFragmentNoMoreFragments = ipv4Header4.toByteArray()
        assertEquals(0x00u, doFragmentNoMoreFragments[6].toUInt())
        val parsedHeader4 = Ipv4Header.fromStream(ByteBuffer.wrap(doFragmentNoMoreFragments))
        assertEquals(ipv4Header4, parsedHeader4)
    }
}
