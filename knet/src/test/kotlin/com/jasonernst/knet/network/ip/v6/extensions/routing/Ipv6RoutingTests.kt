package com.jasonernst.knet.network.ip.v6.extensions.routing

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v6.extenions.routing.FatalRoutingException
import com.jasonernst.knet.network.ip.v6.extenions.routing.Ipv6Routing
import com.jasonernst.knet.network.ip.v6.extenions.routing.Ipv6RoutingType
import com.jasonernst.knet.network.ip.v6.extenions.routing.Ipv6Type2Routing
import com.jasonernst.knet.network.ip.v6.extenions.routing.NonFatalRoutingException
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import kotlin.random.Random

class Ipv6RoutingTests {
    @Test fun toFromStream() {
        val logger = LoggerFactory.getLogger(javaClass)
        val homeAddress = ByteArray(16)
        Random.nextBytes(homeAddress)
        val ipv6Type2Routing = Ipv6Type2Routing(homeAddress = homeAddress)
        ipv6Type2Routing.nextHeader = IpType.UDP.value
        val stream = ByteBuffer.wrap(ipv6Type2Routing.toByteArray())
        val stringDumper = StringPacketDumper()
        logger.debug("{}", stringDumper.dumpBufferToString(stream))
        val nextHeader = stream.get().toUByte()
        val length = stream.get().toUByte()
        val parsed = Ipv6Routing.fromStream(stream = stream, nextHeader = nextHeader, length = length)
        assertEquals(ipv6Type2Routing, parsed)
        assertArrayEquals(ipv6Type2Routing.homeAddress, (parsed as Ipv6Type2Routing).homeAddress)
    }

    @Test fun type2HashcodeTest() {
        val homeAddress = ByteArray(16)
        Random.nextBytes(homeAddress)
        val ipv6Type2Routing = Ipv6Type2Routing(homeAddress = homeAddress)

        val hashMap = hashMapOf(ipv6Type2Routing to "test")
        assertEquals("test", hashMap[ipv6Type2Routing])
    }

    @Test fun type2EqualsTest() {
        val homeAddress = ByteArray(16)
        Random.nextBytes(homeAddress)
        val ipv6Type2Routing = Ipv6Type2Routing(homeAddress = homeAddress)
        val ipv6Type2Routing2 = Ipv6Type2Routing(homeAddress = homeAddress)
        assertEquals(ipv6Type2Routing, ipv6Type2Routing2)
        assertEquals(ipv6Type2Routing, ipv6Type2Routing)
        assertNotEquals(ipv6Type2Routing, null)

        val homeAddress2 = ByteArray(16)
        Random.nextBytes(homeAddress2)
        val ipv6Type2Routing3 = Ipv6Type2Routing(homeAddress = homeAddress2)
        assertNotEquals(ipv6Type2Routing, ipv6Type2Routing3)

        val ipv6Type2Routing4 = Ipv6Type2Routing(homeAddress = homeAddress, nextHeader = 1u)
        assertNotEquals(ipv6Type2Routing, ipv6Type2Routing4)
    }

    @Test fun type2BadHomeAddressSize() {
        val homeAddress = ByteArray(15)
        assertThrows<IllegalArgumentException> {
            Ipv6Type2Routing(homeAddress = homeAddress)
        }

        assertThrows<PacketTooShortException> {
            val stream = ByteBuffer.wrap(byteArrayOf(0, 0, 0, 0))
            Ipv6Type2Routing.fromStream(
                IpType.TCP.value,
                2u,
                Ipv6RoutingType.Type2RoutingHeader,
                1u,
                stream,
            )
        }
    }

    @Test fun type2BadStream() {
        val homeAddress = ByteArray(20)
        Random.nextBytes(homeAddress)
        val stream = ByteBuffer.wrap(homeAddress)
        assertThrows<IllegalArgumentException> {
            Ipv6Type2Routing.fromStream(
                IpType.TCP.value,
                2u,
                Ipv6RoutingType.SourceRouteDeprecated,
                1u,
                stream,
            )
        }

        assertThrows<IllegalArgumentException> {
            Ipv6Type2Routing.fromStream(
                IpType.TCP.value,
                2u,
                Ipv6RoutingType.Type2RoutingHeader,
                5u,
                stream,
            )
        }
    }

    @Test fun fatalNonFatalException() {
        val logger = LoggerFactory.getLogger(javaClass)
        val sourceDeprecated = Ipv6Routing(IpType.TCP.value, 0u, Ipv6RoutingType.SourceRouteDeprecated, 0u)
        val stream = ByteBuffer.wrap(sourceDeprecated.toByteArray())
        logger.debug("{}", StringPacketDumper().dumpBufferToString(stream))
        val nextHeader = stream.get().toUByte()
        val length = stream.get().toUByte()
        assertThrows<NonFatalRoutingException> {
            Ipv6Routing.fromStream(
                stream = stream,
                nextHeader = nextHeader,
                length = length,
            )
        }
        val sourceDeprecated2 = Ipv6Routing(IpType.TCP.value, 0u, Ipv6RoutingType.SourceRouteDeprecated, 1u)
        val stream2 = ByteBuffer.wrap(sourceDeprecated2.toByteArray())
        val nextHeader2 = stream2.get().toUByte()
        val length2 = stream2.get().toUByte()
        assertThrows<FatalRoutingException> {
            Ipv6Routing.fromStream(
                stream = stream2,
                nextHeader = nextHeader2,
                length = length2,
            )
        }

        val nimrodDeprecated = Ipv6Routing(IpType.TCP.value, 0u, Ipv6RoutingType.NimrodDeprecated, 0u)
        val stream3 = ByteBuffer.wrap(nimrodDeprecated.toByteArray())
        val nextHeader3 = stream3.get().toUByte()
        val length3 = stream3.get().toUByte()
        assertThrows<FatalRoutingException> {
            Ipv6Routing.fromStream(
                stream = stream3,
                nextHeader = nextHeader3,
                length = length3,
            )
        }
    }

    @Test fun unsupportedRoutingType() {
        val unsupported = Ipv6Routing(IpType.TCP.value, 0u, Ipv6RoutingType.Reserved, 0u)
        val stream = ByteBuffer.wrap(unsupported.toByteArray())
        val nextHeader = stream.get().toUByte()
        val length = stream.get().toUByte()
        assertThrows<IllegalArgumentException> {
            Ipv6Routing.fromStream(
                stream = stream,
                nextHeader = nextHeader,
                length = length,
            )
        }
    }
}
