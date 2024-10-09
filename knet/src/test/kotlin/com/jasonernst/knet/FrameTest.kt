package com.jasonernst.knet

import com.jasonernst.knet.datalink.EthernetHeader
import com.jasonernst.knet.datalink.MacAddress
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6HopByHopOptions
import com.jasonernst.packetdumper.filedumper.TextFilePacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import java.io.FileNotFoundException
import java.nio.ByteBuffer

class FrameTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test fun toFromStream() {
        val ethernetHeader = EthernetHeader()
        val stream = ByteBuffer.wrap(ethernetHeader.toByteArray())
        val newEthernetHeader = EthernetHeader.fromStream(stream)
        assertEquals(ethernetHeader, newEthernetHeader)
    }

    @Test fun ivp6FrameFromFile() {
        val filename = "/test_packets/ipv6_hop_to_hop_icmpv6.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val readBuffer = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", readBuffer.limit())

        // first parse the dummy ethernet header that has been added
        val ethernetHeader = EthernetHeader.fromStream(readBuffer)
        logger.debug("Ethernet header: {}", ethernetHeader)
        assertEquals(MacAddress.DUMMY_MAC_DEST, ethernetHeader.source)
        assertEquals(MacAddress.DUMMY_MAC_SOURCE, ethernetHeader.destination)

        // next parse the remaining headers
        val packet = Packet.fromStream(readBuffer)

        val ipHeader = packet.ipHeader
        assertTrue(ipHeader is Ipv6Header)
        val ipv6Header = ipHeader as Ipv6Header

        // ensure we have a hop by hop header
        assertTrue(ipv6Header.extensionHeaders.isNotEmpty())
        val hopByHopHeader = ipv6Header.extensionHeaders[0]
        assertTrue(hopByHopHeader is Ipv6HopByHopOptions)
    }
}
