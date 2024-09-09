package com.jasonernst.knet.nextheader

import com.jasonernst.icmp_common.v4.ICMPv4EchoPacket
import com.jasonernst.icmp_common.v6.ICMPv6EchoPacket
import com.jasonernst.knet.ip.IPType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class ICMPTest {
    @Test
    fun icmpv4() {
        val icmp = ICMPNextHeaderWrapper(ICMPv4EchoPacket(id = 1u, sequence = 2u, data = "hello".toByteArray()), IPType.ICMP.value, "ICMP")
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = NextHeader.fromStream(stream, IPType.ICMP.value) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }

    @Test fun icmpv6() {
        val icmp =
            ICMPNextHeaderWrapper(ICMPv6EchoPacket(id = 1u, sequence = 2u, data = "hello".toByteArray()), IPType.IPV6_ICMP.value, "ICMPv6")
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = NextHeader.fromStream(stream, IPType.IPV6_ICMP.value) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }
}
