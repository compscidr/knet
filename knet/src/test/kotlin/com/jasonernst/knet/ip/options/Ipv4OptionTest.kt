package com.jasonernst.knet.ip.options

import com.jasonernst.knet.PacketTooShortException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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

    @Test fun copiedClassTypeTest() {
        val option =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.StreamId)
        val typeByte = option.toByteArray()[0]
        val copied = typeByte.toInt() and 0b10000000 == 0b10000000
        assertTrue(copied)
        val classByte = (typeByte.toInt() and 0b01100000 shr 5).toUByte()
        assertEquals(Ipv4OptionClassType.DebuggingAndMeasurement.kind, classByte)
        val kind = (typeByte.toInt() and 0b00011111).toUByte()
        assertEquals(Ipv4OptionType.StreamId.kind, kind)
    }

    @Test fun unknownOption() {
        // unhandled option, but in list
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte(), 0x04, 0x00, 0x00))
        val parsedOptions = Ipv4Option.parseOptions(stream, 4)
        assertTrue(parsedOptions[0] is Ipv4OptionUnknown)

        // unhandled option, not in list
        val stream2 = ByteBuffer.wrap(byteArrayOf(0x11.toByte(), 0x04, 0x00, 0x00))
        val parsedOptions2 = Ipv4Option.parseOptions(stream2, 4)
        assertTrue(parsedOptions2[0] is Ipv4OptionUnknown)

        // unknown option good path
        val unhandledOption =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        val stream3 = ByteBuffer.wrap(unhandledOption.toByteArray())
        val parsedOptions3 = Ipv4Option.parseOptions(stream3)
        assertEquals(1, parsedOptions3.size)
        assertEquals(unhandledOption, parsedOptions3[0])
    }

    @Test fun unknownOptionTooShortLength() {
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte()))
        assertThrows<PacketTooShortException> {
            Ipv4Option.parseOptions(stream)
        }
    }

    @Test fun unknownOptionTooShortLengthOk() {
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte(), 0x04, 0x00))
        assertThrows<PacketTooShortException> {
            Ipv4Option.parseOptions(stream, 3)
        }
    }

    @Test fun unknownOptionEquals() {
        val option1 =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        val option2 =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        assertEquals(option1, option2)

        val option3 = Ipv4OptionEndOfOptionList(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement)
        assertNotEquals(option1, option3)

        val option4 =
            Ipv4OptionUnknown(isCopied = false, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        assertNotEquals(option1, option4)

        val option5 = Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.Control, type = Ipv4OptionType.Unknown)
        assertNotEquals(option1, option5)

        val option6 =
            Ipv4OptionUnknown(
                isCopied = true,
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                type = Ipv4OptionType.EndOfOptionList,
            )
        assertNotEquals(option1, option6)

        val option7 =
            Ipv4OptionUnknown(
                isCopied = true,
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                type = Ipv4OptionType.Unknown,
                size = 10u,
            )
        assertNotEquals(option1, option7)

        val option8 =
            Ipv4OptionUnknown(
                isCopied = true,
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                type = Ipv4OptionType.Unknown,
                size = 10u,
                data = byteArrayOf(0x00, 0x01, 0x02),
            )
        assertNotEquals(option7, option8)
    }

    @Test fun unknownOptionHashCodeTest() {
        val map: MutableMap<Ipv4OptionUnknown, String> = mutableMapOf()
        val option1 =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        map[option1] = "test"
        assertTrue(map.containsKey(option1))
    }
}
