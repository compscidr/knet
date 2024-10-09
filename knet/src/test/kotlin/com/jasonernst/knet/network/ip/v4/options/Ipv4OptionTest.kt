package com.jasonernst.knet.network.ip.v4.options

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.transport.tcp.options.TcpOptionNoOperation
import org.junit.jupiter.api.Assertions
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

    @Test fun mismatchedOptionsLengthIhl() {
        val options =
            arrayListOf(
                Ipv4OptionNoOperation(true, Ipv4OptionClassType.Control),
                Ipv4OptionEndOfOptionList(true, Ipv4OptionClassType.Control),
            )
        assertThrows<IllegalArgumentException> {
            Ipv4Header(options = options)
        }
    }

    @Test fun correctOptionsLengthButTooShort() {
        val options =
            arrayListOf(
                Ipv4OptionNoOperation(true, Ipv4OptionClassType.Control),
                Ipv4OptionEndOfOptionList(true, Ipv4OptionClassType.Control),
            )
        val ipHeader = Ipv4Header(ihl = 6u, options = options)
        val stream = ByteBuffer.wrap(ipHeader.toByteArray())
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            Ipv4Header.fromStream(stream)
        }
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
        val data = byteArrayOf(0x00, 0x00)
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte(), 0x04, data[0], data[1]))
        val parsedOptions = Ipv4Option.parseOptions(stream, 4)
        assertEquals(1, parsedOptions.size)
        assertTrue(parsedOptions[0] is Ipv4OptionUnknown)
        val parsedOption = parsedOptions[0] as Ipv4OptionUnknown
        for (i in data.indices) {
            Assertions.assertEquals(data[i], parsedOption.data[i])
        }

        // unhandled option, not in list
        val stream2 = ByteBuffer.wrap(byteArrayOf(0x11.toByte(), 0x04, 0x00, 0x00))
        val parsedOptions2 = Ipv4Option.parseOptions(stream2, 4)
        assertEquals(1, parsedOptions2.size)
        assertTrue(parsedOptions2[0] is Ipv4OptionUnknown)

        // unknown option good path
        val unhandledOption =
            Ipv4OptionUnknown(isCopied = true, optionClass = Ipv4OptionClassType.DebuggingAndMeasurement, type = Ipv4OptionType.Unknown)
        val stream3 = ByteBuffer.wrap(unhandledOption.toByteArray())
        val parsedOptions3 = Ipv4Option.parseOptions(stream3)
        assertEquals(1, parsedOptions3.size)
        assertEquals(unhandledOption, parsedOptions3[0])

        val otherClass = TcpOptionNoOperation()
        assertNotEquals(unhandledOption, otherClass)
        assertNotEquals(unhandledOption, null)
        assertEquals(unhandledOption, unhandledOption)
    }

    @Test fun unknownOptionTooShortLength() {
        val stream = ByteBuffer.wrap(byteArrayOf(0xFE.toByte()))
        assertThrows<PacketTooShortException> {
            Ipv4Option.parseOptions(stream)
        }

        val option = Ipv4OptionUnknown(size = 0u)
        assertThrows<IllegalArgumentException> {
            option.toByteArray()
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

    @Test fun ipv4OptionSecurity() {
        val option =
            Ipv4OptionSecurity(
                isCopied = true,
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                type = Ipv4OptionType.Security,
                security = Ipv4OptionSecurityType.Confidential,
                compartment = 1234u,
                handlingRestrictions = 5678u,
                tcc = 9102u,
            )
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream size: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
        val parsedOption = parsedOptions[0] as Ipv4OptionSecurity
        assertEquals(option.security, parsedOption.security)
        assertEquals(option.compartment, parsedOption.compartment)
        assertEquals(option.handlingRestrictions, parsedOption.handlingRestrictions)
        assertEquals(option.tcc, parsedOption.tcc)
    }

    @Test fun ipv4OptionSecurityTooShort() {
        val option = Ipv4OptionSecurity()
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            Ipv4Option.parseOptions(stream)
        }

        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionSecurity.fromStream(stream, option.isCopied, option.optionClass, option.size)
        }
    }

    @Test
    fun ipv4OptionSecurityTypeBad() {
        assertThrows<IllegalArgumentException> {
            Ipv4OptionSecurityType.fromKind(0x20u)
        }
    }

    @Test
    fun ipv4OptionLooseSourceAndRecordRoute() {
        val option = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream length: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
    }

    @Test fun ipv4OptionLooseSourceAndRecordRouteTooShort() {
        val option = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionLooseSourceAndRecordRoute.fromStream(stream, true, Ipv4OptionClassType.DebuggingAndMeasurement, 6u)
        }
    }

    @Test fun ipv4OptionLooseSourceAndRecordRouteEquals() {
        val option1 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val option2 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertEquals(option1, option2)

        val option3 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 1u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option3)

        val option4 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x03))
        assertNotEquals(option1, option4)

        val option5 = TcpOptionNoOperation()
        assertNotEquals(option1, option5)
        assertNotEquals(option1, null)
        assertEquals(option1, option1)
        assertEquals(option1.pointer, option1.pointer)
        for (i in option1.routeData.indices) {
            Assertions.assertEquals(option1.routeData[i], option1.routeData[i])
        }

        val option6 = Ipv4OptionLooseSourceAndRecordRoute(isCopied = false, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option6)

        val option7 =
            Ipv4OptionLooseSourceAndRecordRoute(
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                pointer = 0u,
                routeData = byteArrayOf(0x00, 0x01, 0x02),
            )
        assertNotEquals(option1, option7)

        val option8 =
            Ipv4OptionLooseSourceAndRecordRoute(type = Ipv4OptionType.StreamId, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option8)

        val option9 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u)
        assertNotEquals(option1, option9)
    }

    @Test fun ipv4OptionLooseSourceAndRecordRouteHashCode() {
        val map: MutableMap<Ipv4OptionLooseSourceAndRecordRoute, String> = mutableMapOf()
        val option1 = Ipv4OptionLooseSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        map[option1] = "test"
        assertTrue(map.containsKey(option1))
    }

    @Test fun ipv4OptionStrictSourceAndRecordRoute() {
        val option = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream length: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
    }

    @Test fun ipv4OptionStrictSourceAndRecordRouteTooShort() {
        val option = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionStrictSourceAndRecordRoute.fromStream(stream, true, Ipv4OptionClassType.DebuggingAndMeasurement, 6u)
        }
    }

    @Test fun ipv4OptionStrictSourceAndRecordRouteEquals() {
        val option1 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val option2 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertEquals(option1, option2)

        val option3 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 1u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option3)

        val option4 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x03))
        assertNotEquals(option1, option4)

        val option5 = TcpOptionNoOperation()
        assertNotEquals(option1, option5)
        assertNotEquals(option1, null)
        assertEquals(option1, option1)
        assertEquals(option1.pointer, option1.pointer)
        for (i in option1.routeData.indices) {
            Assertions.assertEquals(option1.routeData[i], option1.routeData[i])
        }

        val option6 = Ipv4OptionStrictSourceAndRecordRoute(isCopied = false, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option6)

        val option7 =
            Ipv4OptionStrictSourceAndRecordRoute(
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                pointer = 0u,
                routeData = byteArrayOf(0x00, 0x01, 0x02),
            )
        assertNotEquals(option1, option7)

        val option8 =
            Ipv4OptionStrictSourceAndRecordRoute(type = Ipv4OptionType.StreamId, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option8)

        val option9 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u)
        assertNotEquals(option1, option9)
    }

    @Test fun ipv4OptionStrictSourceAndRecordRouteHashCode() {
        val map: MutableMap<Ipv4OptionStrictSourceAndRecordRoute, String> = mutableMapOf()
        val option1 = Ipv4OptionStrictSourceAndRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        map[option1] = "test"
        assertTrue(map.containsKey(option1))
    }

    @Test fun ipv4OptionRecordRoute() {
        val option = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02, 0x03))
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream length: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
    }

    @Test fun ipv4OptionRecordRouteTooShort() {
        val option = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionRecordRoute.fromStream(stream, true, Ipv4OptionClassType.DebuggingAndMeasurement, 6u)
        }
    }

    @Test fun ipv4OptionRecordRouteEquals() {
        val option1 = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        val option2 = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertEquals(option1, option2)
        assertEquals(option1.pointer, option2.pointer)
        for (i in option1.routeData.indices) {
            Assertions.assertEquals(option1.routeData[i], option2.routeData[i])
        }

        val option3 = Ipv4OptionRecordRoute(pointer = 1u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option3)

        val option4 = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x03))
        assertNotEquals(option1, option4)

        val option5 = TcpOptionNoOperation()
        assertNotEquals(option1, option5)
        assertNotEquals(option1, null)
        assertEquals(option1, option1)

        val option6 = Ipv4OptionRecordRoute(isCopied = true, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option6)

        val option7 =
            Ipv4OptionRecordRoute(
                optionClass = Ipv4OptionClassType.DebuggingAndMeasurement,
                pointer = 0u,
                routeData = byteArrayOf(0x00, 0x01, 0x02),
            )
        assertNotEquals(option1, option7)

        val option8 =
            Ipv4OptionRecordRoute(type = Ipv4OptionType.StreamId, pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        assertNotEquals(option1, option8)
    }

    @Test fun ipv4OptionRecordRouteHashCode() {
        val map: MutableMap<Ipv4OptionRecordRoute, String> = mutableMapOf()
        val option1 = Ipv4OptionRecordRoute(pointer = 0u, routeData = byteArrayOf(0x00, 0x01, 0x02))
        map[option1] = "test"
        assertTrue(map.containsKey(option1))
    }

    @Test fun ipv4OptionStreamIdentifier() {
        val option = Ipv4OptionStreamIdentifier(streamId = 0x1234u)
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream length: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
    }

    @Test fun ipv4OptionStreamIdentifierTooShort() {
        val option = Ipv4OptionStreamIdentifier(streamId = 0x1234u)
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionStreamIdentifier.fromStream(stream, true, Ipv4OptionClassType.DebuggingAndMeasurement, 6u)
        }
    }

    @Test fun ipv4OptionStreamIdentifierEquals() {
        val option1 = Ipv4OptionStreamIdentifier(streamId = 0x1234u)
        val option2 = Ipv4OptionStreamIdentifier(streamId = 0x1234u)
        assertEquals(option1, option2)

        val option3 = Ipv4OptionStreamIdentifier(streamId = 0x1235u)
        assertNotEquals(option1, option3)
    }

    @Test fun ipv4OptionTimestamp() {
        val option =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        val stream = ByteBuffer.wrap(option.toByteArray())
        logger.debug("Stream length: ${stream.limit()}")
        val parsedOptions = Ipv4Option.parseOptions(stream)
        assertEquals(1, parsedOptions.size)
        assertEquals(option, parsedOptions[0])
        val parsedOption = parsedOptions[0] as Ipv4OptionInternetTimestamp
        assertEquals(option.pointer, parsedOption.pointer)
        assertEquals(option.overFlowFlags, parsedOption.overFlowFlags)
        assertEquals(option.internetAddress, parsedOption.internetAddress)
        assertEquals(option.timestamps, parsedOption.timestamps)
    }

    @Test fun ipv4OptionTimestampTooShort() {
        val option =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        val stream = ByteBuffer.wrap(option.toByteArray())
        stream.limit(stream.limit() - 1)
        stream.position(2)
        assertThrows<PacketTooShortException> {
            Ipv4OptionInternetTimestamp.fromStream(stream, true, Ipv4OptionClassType.DebuggingAndMeasurement, option.size)
        }
    }

    @Test fun ipv4OptionTimestampEquals() {
        val option1 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        val option2 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        assertEquals(option1, option2)

        val option3 =
            Ipv4OptionInternetTimestamp(
                pointer = 1u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        assertNotEquals(option1, option3)

        val option4 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x02u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        assertNotEquals(option1, option4)

        val option5 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5679u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        assertNotEquals(option1, option5)

        val option6 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1235u, 0x5678u),
            )
        assertNotEquals(option1, option6)

        val option7 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5679u),
            )
        assertNotEquals(option1, option7)
    }

    @Test fun ipv4OptionTimestampHashCode() {
        val map: MutableMap<Ipv4OptionInternetTimestamp, String> = mutableMapOf()
        val option1 =
            Ipv4OptionInternetTimestamp(
                pointer = 0u,
                overFlowFlags = 0x01u,
                internetAddress = 0x5678u,
                timestamps = listOf(0x1234u, 0x5678u),
            )
        map[option1] = "test"
        assertTrue(map.containsKey(option1))
    }
}
