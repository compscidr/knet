package com.jasonernst.knet.icmp

import com.jasonernst.icmp_common.ICMPHeader
import com.jasonernst.icmp_common.v4.ICMPv4EchoPacket
import com.jasonernst.icmp_common.v6.ICMPv6EchoPacket
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class ICMPTest {
    @Test
    fun icmpv4() {
        val icmp = ICMPv4EchoPacket(id = 1u, sequence = 2u, data = "hello".toByteArray())
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = ICMPHeader.fromStream(stream)
        assertEquals(icmp, parsed)
    }

    @Test fun icmpv6() {
        val icmp = ICMPv6EchoPacket(id = 1u, sequence = 2u, data = "hello".toByteArray())
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = ICMPHeader.fromStream(stream, isIcmpV4 = false)
        assertEquals(icmp, parsed)
    }
}
