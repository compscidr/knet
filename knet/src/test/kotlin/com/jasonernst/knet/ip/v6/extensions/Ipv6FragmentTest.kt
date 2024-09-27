package com.jasonernst.knet.ip.v6.extensions

import com.jasonernst.knet.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random

class Ipv6FragmentTest {
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
}
