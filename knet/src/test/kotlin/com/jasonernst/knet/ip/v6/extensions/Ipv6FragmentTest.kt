package com.jasonernst.knet.ip.v6.extensions

import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.Ipv6Header
import com.jasonernst.knet.ip.v6.extenions.Ipv6Fragment
import com.jasonernst.knet.ip.v6.extenions.Ipv6HopByHopOptions
import com.jasonernst.knet.transport.tcp.TcpHeader
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer
import kotlin.random.Random

class Ipv6FragmentTest {
    @Test
    fun toAndFromStream() {
        val fragmentHeader = Ipv6Fragment()
        val stream = ByteBuffer.wrap(fragmentHeader.toByteArray())
        var nextHeader = stream.get().toUByte()
        stream.get() // skip over length
        var parsedFragmentHeader = Ipv6Fragment.fromStream(stream, nextHeader)
        assertEquals(fragmentHeader, parsedFragmentHeader)

        val fragmentWithMore = Ipv6Fragment(moreFlag = true)
        fragmentWithMore.nextHeader = IpType.UDP.value // make sure the setter is working
        val stream2 = ByteBuffer.wrap(fragmentWithMore.toByteArray())
        nextHeader = stream2.get().toUByte()
        stream2.get() // skip over length
        parsedFragmentHeader = Ipv6Fragment.fromStream(stream2, nextHeader)
        assertEquals(fragmentWithMore, parsedFragmentHeader)
        assertTrue(parsedFragmentHeader.moreFlag)
        assertEquals(IpType.UDP.value, parsedFragmentHeader.nextHeader)
    }

    @Test
    fun fragmentReassembly() {
        val payload = ByteArray(5000)
        Random.Default.nextBytes(payload)
        val tcpHeader = TcpHeader()
        val ipPayloadLength = payload.size.toUInt() + tcpHeader.getHeaderLength()
        val ipv6Header = Ipv6Header(payloadLength = ipPayloadLength.toUShort())
        val fragments = ipv6Header.fragment(1000u, tcpHeader, payload)
        assertEquals(6, fragments.size) // 5 won't quite fit with headers
        val reassembled = Ipv6Header.reassemble(fragments)
        assertEquals(ipv6Header, reassembled.first)
        assertEquals(tcpHeader, reassembled.second)
        assertArrayEquals(payload, reassembled.third)
    }

    @Test fun reassembleEmptyFragments() {
        assertThrows<IllegalArgumentException> {
            Ipv6Header.reassemble(listOf())
        }
    }

    @Test fun fragmentBadMaxSize() {
        assertThrows<IllegalArgumentException> {
            Ipv6Header().fragment(1u, TcpHeader(), ByteArray(0))
        }
    }

    @Test fun reassmbleWithoutFirstFragmentHeader() {
        val fragments = listOf(Triple(Ipv6Header(), TcpHeader(), ByteArray(0)))
        assertThrows<IllegalArgumentException> {
            Ipv6Header.reassemble(fragments)
        }
    }

    // tests that the reassembly works when the fragments are out of order,
    // ie), the first fragment is not the first in the list
    @Test fun reassemblyWithExtraExtensionHeaders() {
        val payload = ByteArray(5000)
        Random.Default.nextBytes(payload)
        val tcpHeader = TcpHeader()
        val ipPayloadLength = payload.size.toUInt() + tcpHeader.getHeaderLength()
        val extensionHeaders = listOf(Ipv6HopByHopOptions())
        val extensionHeaderLength = extensionHeaders.sumOf { it.getExtensionLengthInBytes() }
        val totalLength = ipPayloadLength + extensionHeaderLength.toUInt()
        val ipv6Header = Ipv6Header(payloadLength = totalLength.toUShort(), extensionHeaders = extensionHeaders)
        val fragments = ipv6Header.fragment(1000u, tcpHeader, payload)
        assertEquals(6, fragments.size) // 5 won't quite fit with headers

        val reassembled = Ipv6Header.reassemble(fragments)
        assertEquals(ipv6Header, reassembled.first)
        assertEquals(tcpHeader, reassembled.second)
        assertArrayEquals(payload, reassembled.third)
    }

    @Test fun reassemblyWithFragmentWithoutFragmentHeader() {
        val payload = ByteArray(5000)
        Random.Default.nextBytes(payload)
        val tcpHeader = TcpHeader()
        val ipPayloadLength = payload.size.toUInt() + tcpHeader.getHeaderLength()
        val extensionHeaders = listOf(Ipv6HopByHopOptions())
        val extensionHeaderLength = extensionHeaders.sumOf { it.getExtensionLengthInBytes() }
        val totalLength = ipPayloadLength + extensionHeaderLength.toUInt()
        val ipv6Header = Ipv6Header(payloadLength = totalLength.toUShort(), extensionHeaders = extensionHeaders)
        val fragments = ipv6Header.fragment(1000u, tcpHeader, payload) as MutableList
        assertEquals(6, fragments.size) // 5 won't quite fit with headers

        val removableExtensionHeaders = fragments[1].first.extensionHeaders
        var removableExtensionHeader: Ipv6Fragment? = null
        for (extensionHeader in removableExtensionHeaders) {
            if (extensionHeader.type == IpType.IPV6_FRAG) {
                removableExtensionHeader = extensionHeader as Ipv6Fragment
                break
            }
        }
        (removableExtensionHeaders as MutableList).remove(removableExtensionHeader!!)

        assertThrows<IllegalArgumentException> { Ipv6Header.reassemble(fragments) }
    }

    @Test fun reassmbleWithMismatchedId() {
        val fragment1 = Ipv6Fragment(identification = 1u)
        val fragment2 = Ipv6Fragment(identification = 2u)
        val fragments =
            listOf(
                Triple(Ipv6Header(extensionHeaders = listOf(fragment1)), TcpHeader(), ByteArray(0)),
                Triple(Ipv6Header(extensionHeaders = listOf(fragment2)), null, ByteArray(0)),
            )
        assertThrows<IllegalArgumentException> { Ipv6Header.reassemble(fragments) }
    }
}
