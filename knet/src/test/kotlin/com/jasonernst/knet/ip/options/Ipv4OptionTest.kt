package com.jasonernst.knet.ip.options

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

class Ipv4OptionTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test fun parseOptions() {
        val options =
            arrayListOf(
                Ipv4OptionNoOperation(true, Ipv4OptionClassType.Control),
                Ipv4OptionEndOfOptionList(true, Ipv4OptionClassType.Control),
            )
        val optionSize = options.sumOf { it.size.toInt() }
        val stream = ByteBuffer.allocate(optionSize)
        for (option in options) {
            stream.put(option.toByteArray())
        }
        stream.rewind()
        val parsedOptions = Ipv4Option.parseOptions(stream, optionSize)
        assertEquals(options, parsedOptions)
    }

    @Test fun unknownOption() {
        // unhandled option, but in list
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte(), 0x04, 0x00, 0x00))
        val parsedOptions = Ipv4Option.parseOptions(stream, 4)
        assertTrue(parsedOptions[0] is Ipv4OptionUnknown)

        // unhandled option, not in list
        val stream2 = ByteBuffer.wrap(byteArrayOf(0x02.toByte(), 0x04, 0x00, 0x00))
        val parsedOptions2 = Ipv4Option.parseOptions(stream2, 4)
        assertTrue(parsedOptions2[0] is Ipv4OptionUnknown)
    }

    @Test fun unknownOptionTooShort() {
        // wip
    }
}
