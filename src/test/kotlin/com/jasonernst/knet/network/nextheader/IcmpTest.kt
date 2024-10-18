package com.jasonernst.knet.network.nextheader

import com.jasonernst.icmp_common.v4.ICMPv4EchoPacket
import com.jasonernst.icmp_common.v6.ICMPv6EchoPacket
import com.jasonernst.knet.network.ip.IpType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class IcmpTest {
    @Test
    fun icmpv4() {
        val icmp =
            ICMPNextHeaderWrapper(
                ICMPv4EchoPacket(
                    id = 1u,
                    sequence = 2u,
                    data = "hello".toByteArray(),
                ),
                IpType.ICMP.value,
                "ICMP",
            )
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = NextHeader.Companion.fromStream(stream, IpType.ICMP.value) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }

    @Test fun icmpv6() {
        val icmp =
            ICMPNextHeaderWrapper(
                ICMPv6EchoPacket(
                    id = 1u,
                    sequence = 2u,
                    data = "hello".toByteArray(),
                ),
                IpType.IPV6_ICMP.value,
                "ICMPv6",
            )
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = NextHeader.Companion.fromStream(stream, IpType.IPV6_ICMP.value) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }
}
