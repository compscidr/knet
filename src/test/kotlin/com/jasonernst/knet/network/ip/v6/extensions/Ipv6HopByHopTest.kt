package com.jasonernst.knet.network.ip.v6.extensions

import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6HopByHopOptions
import com.jasonernst.knet.network.ip.v6.extenions.Ipv6Tlv
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

class Ipv6HopByHopTest {
    @Test
    fun lengthOptionsMismatch() {
        assertThrows<IllegalArgumentException> {
            Ipv6HopByHopOptions(
                optionData =
                    listOf(
                        Ipv6Tlv(),
                        Ipv6Tlv(),
                    ),
            )
        }

        assertThrows<IllegalArgumentException> {
            Ipv6HopByHopOptions(
                length = 3u,
                optionData =
                    listOf(
                        Ipv6Tlv(),
                    ),
            )
        }
    }

    @Test fun optionDataTest() {
        val optionData =
            listOf(
                Ipv6Tlv(),
            )
        val hopByHopOptions = Ipv6HopByHopOptions(optionData = optionData)
        assertEquals(hopByHopOptions.optionData, optionData)
    }

    @Test fun toFromStream() {
        val logger = LoggerFactory.getLogger(javaClass)
        val hopByHopOptions = Ipv6HopByHopOptions()
        hopByHopOptions.nextHeader = IpType.UDP.value
        val stream = ByteBuffer.wrap(hopByHopOptions.toByteArray())
        val stringPacketDumper = StringPacketDumper(logger)
        stringPacketDumper.dumpBuffer(stream)
        val parsedNextHeader = stream.get().toUByte()
        assertEquals(hopByHopOptions.nextHeader, parsedNextHeader)
        val parsedLength = stream.get().toUByte()
        assertEquals(hopByHopOptions.length, parsedLength)
        val parsedOptions = Ipv6HopByHopOptions.fromStream(stream, parsedNextHeader, parsedLength)
        assertEquals(hopByHopOptions, parsedOptions)
    }
}
