package com.jasonernst.knet

import com.jasonernst.knet.ip.IpHeader
import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v4.Ipv4Header
import com.jasonernst.knet.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import kotlin.random.Random

class PacketTests {
    @Test
    fun packetTooShort() {
        val payload = "test".toByteArray()
        val sourcePort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val sourceAddress = InetSocketAddress(InetAddress.getByName("::1"), sourcePort)
        val destPort = Random.Default.nextInt(2 * Short.MAX_VALUE - 1)
        val destinationAddress = InetSocketAddress(InetAddress.getByName("::2"), destPort)
        val tcpHeader =
            TcpHeader(
                sourcePort = sourcePort.toUShort(),
                destinationPort = destPort.toUShort(),
                sequenceNumber = 100u,
                acknowledgementNumber = 500u,
                windowSize = 35000.toUShort(),
            )
        val ipHeader =
            IpHeader.createIPHeader(
                sourceAddress.address,
                destinationAddress.address,
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt() + payload.size,
            )
        val packet = Packet(ipHeader, tcpHeader, payload)
        val stream = ByteBuffer.wrap(packet.toByteArray())
        stream.limit(stream.limit() - 3)
        assertThrows<PacketTooShortException> {
            Packet.fromStream(stream)
        }
    }

    @Test
    fun packetHashCodeTest() {
        val map: MutableMap<Packet, Int> = mutableMapOf()
        val ipHeader = Ipv4Header()
        val tcpHeader = TcpHeader()
        val packet = Packet(ipHeader, tcpHeader, ByteArray(0))
        map[packet] = 1
        assertTrue(map.containsKey(packet))
        assertEquals(map[packet], 1)
    }

    @Test
    fun equalityChecks() {
        val ipHeader = Ipv4Header()
        val tcpHeader = TcpHeader()
        val packet = Packet(ipHeader, tcpHeader, ByteArray(0))

        assertFalse(packet.equals(this))

        val ipHeader2 = Ipv6Header()
        val packet2 = Packet(ipHeader2, tcpHeader, ByteArray(0))
        assertFalse(packet == packet2)

        val udpHeader = UdpHeader()
        val packet3 = Packet(ipHeader, udpHeader, ByteArray(0))
        assertFalse(packet == packet3)

        val packet4 = Packet(ipHeader, tcpHeader, ByteArray(1))
        assertFalse(packet == packet4)

        assertNotEquals(packet, null)
        assertNotEquals(packet, Any())
        assertEquals(packet, packet)

        val packet5 = packet.copy()
        assertEquals(packet.ipHeader, packet5.ipHeader)
        assertEquals(packet.nextHeaders, packet5.nextHeaders)
        assertArrayEquals(packet.payload, packet5.payload)
    }
}
