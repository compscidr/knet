package com.jasonernst.knet.ip.v6.extensions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.Ipv6Header
import com.jasonernst.knet.ip.v6.extenions.Ipv6DestinationOptions
import com.jasonernst.knet.ip.v6.extenions.Ipv6ExtensionHeader
import com.jasonernst.knet.ip.v6.extenions.Ipv6Fragment
import com.jasonernst.knet.ip.v6.extenions.Ipv6HopByHopOptions
import com.jasonernst.knet.ip.v6.extenions.routing.Ipv6Type2Routing
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.net.Inet6Address
import java.nio.ByteBuffer
import kotlin.random.Random

class Ipv6ExtensionHeaderTest {
    @Test fun packetTooShort() {
        val stream = ByteBuffer.wrap(byteArrayOf(0x00))
        assertThrows<PacketTooShortException> {
            Ipv6ExtensionHeader.fromStream(stream, IpType.IPV6_FRAG)
        }
    }

    @Test fun multipleExtensionHeaders() {
        val homeAddress = ByteArray(16)
        Random.nextBytes(homeAddress)
        val ipv6ExtensionHeaders =
            listOf<Ipv6ExtensionHeader>(
                Ipv6HopByHopOptions(nextHeader = IpType.IPV6_FRAG.value),
                Ipv6Fragment(nextHeader = IpType.IPV6_OPTS.value),
                Ipv6DestinationOptions(nextHeader = IpType.IPV6_ROUTE.value),
                Ipv6Type2Routing(nextHeader = IpType.TCP.value, homeAddress),
            )
        val payloadLength = ipv6ExtensionHeaders.sumOf { it.length.toInt() }
        val ipv6Header =
            Ipv6Header(
                trafficClass = 0x09u,
                flowLabel = 0x12345u,
                protocol = IpType.HOPOPT.value,
                hopLimit = 0x40u,
                sourceAddress = Inet6Address.getByName("::1"),
                destinationAddress = Inet6Address.getByName("::1"),
                extensionHeaders = ipv6ExtensionHeaders,
                payloadLength = payloadLength.toUShort(),
            )
        val stream = ByteBuffer.wrap(ipv6Header.toByteArray())

        val logger = LoggerFactory.getLogger(javaClass)
        logger.debug("{}", StringPacketDumper().dumpBufferToString(stream))

        val parsed = Ipv6Header.fromStream(stream)
        assertEquals(ipv6Header, parsed)
    }
}
