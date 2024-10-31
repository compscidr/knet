package com.jasonernst.knet.network.nextheader

import com.jasonernst.icmp.common.v4.IcmpV4EchoPacket
import com.jasonernst.icmp.common.v6.IcmpV6EchoPacket
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class IcmpTest {
    @Test
    fun icmpv4() {
        val icmp =
            ICMPNextHeaderWrapper(
                IcmpV4EchoPacket(
                    id = 1u,
                    sequence = 2u,
                    data = "hello".toByteArray(),
                ),
                IpType.ICMP.value,
                "ICMP",
            )
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val ipV4Header = Ipv4Header(protocol = IpType.ICMP.value)
        val parsed = NextHeader.Companion.fromStream(ipV4Header, stream) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }

    @Test fun icmpv6() {
        val ipV6Header = Ipv6Header(protocol = IpType.IPV6_ICMP.value)
        val icmp =
            ICMPNextHeaderWrapper(
                IcmpV6EchoPacket(
                    ipV6Header.sourceAddress,
                    ipV6Header.destinationAddress,
                    id = 1u,
                    sequence = 2u,
                    data = "hello".toByteArray(),
                ),
                IpType.IPV6_ICMP.value,
                "ICMPv6",
            )
        val stream = ByteBuffer.wrap(icmp.toByteArray())
        val parsed = NextHeader.Companion.fromStream(ipV6Header, stream) as ICMPNextHeaderWrapper
        assertEquals(icmp, parsed)
    }
}
