package com.jasonernst.knet.network.icmp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v4.IcmpV4EchoPacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6EchoPacket
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

class IcmpTest {
    @Test
    fun icmpv4() {
        val icmp =
            IcmpNextHeaderWrapper(
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
        val parsed = NextHeader.fromStream(ipV4Header, stream) as IcmpNextHeaderWrapper
        assertEquals(icmp, parsed)
    }

    @Test fun icmpv6() {
        val ipV6Header = Ipv6Header(protocol = IpType.IPV6_ICMP.value)
        val icmp =
            IcmpNextHeaderWrapper(
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
        val parsed = NextHeader.fromStream(ipV6Header, stream) as IcmpNextHeaderWrapper
        assertEquals(icmp, parsed)
    }

    @Test fun icmpV4DestinationUnreachable() {
        val code = IcmpV4DestinationUnreachableCodes.PORT_UNREACHABLE
        val tcpHeader = TcpHeader()
        val ipHeader =
            IpHeader.createIPHeader(
                InetAddress.getByName("127.0.0.1"),
                InetAddress.getByName("127.0.0.1"),
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt(),
            )
        val originalPacket = Packet(ipHeader, tcpHeader, ByteArray(0))
        val packet =
            IcmpFactory.createDestinationUnreachable(
                code,
                InetAddress.getByName("127.0.0.1") as Inet4Address,
                originalPacket,
                1500,
            )
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val parsed = Packet.fromStream(stream)

        assertTrue(parsed.nextHeaders is IcmpNextHeaderWrapper)
        val icmp = (parsed.nextHeaders as IcmpNextHeaderWrapper).icmpHeader
        assertTrue(icmp is IcmpV4DestinationUnreachablePacket)
    }

    @Test fun icmpV6DestinationUnreachable() {
        val code = IcmpV6DestinationUnreachableCodes.PORT_UNREACHABLE
        val tcpHeader = TcpHeader()
        val ipHeader =
            IpHeader.createIPHeader(
                InetAddress.getByName("::1"),
                InetAddress.getByName("::1"),
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt(),
            )
        val originalPacket = Packet(ipHeader, tcpHeader, ByteArray(0))
        val packet =
            IcmpFactory.createDestinationUnreachable(
                code,
                InetAddress.getByName("::1") as Inet6Address,
                originalPacket,
                1500,
            )
        val stream = ByteBuffer.wrap(packet.toByteArray())
        val parsed = Packet.fromStream(stream)

        assertTrue(parsed.nextHeaders is IcmpNextHeaderWrapper)
        val icmp = (parsed.nextHeaders as IcmpNextHeaderWrapper).icmpHeader
        assertTrue(icmp is IcmpV6DestinationUnreachablePacket)
    }
}
