package com.jasonernst.knet.tcp.options

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.IpHeader
import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.options.Ipv4OptionNoOperation
import com.jasonernst.knet.nextheader.NextHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOption
import com.jasonernst.knet.transport.tcp.options.TcpOption.Companion.parseOptions
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.knet.transport.tcp.options.TcpOptionNoOperation
import com.jasonernst.knet.transport.tcp.options.TcpOptionTimestamp
import com.jasonernst.knet.transport.tcp.options.TcpOptionUnsupported
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer

class TcpOptionTests {
    private val stringPacketDumper = StringPacketDumper()
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test
    fun getValueZeroMSS() {
        val res = TcpOptionMaximumSegmentSize(mss = 0u)
        assertEquals(res.mss, 0u.toUShort())
    }

    @Test
    fun getOptionalMSSFromTCPHeaderExists() {
        val mss: UShort = 1440u
        val mssOption = TcpOptionMaximumSegmentSize(mss = mss)
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options = arrayListOf(mssOption),
            )
        val nullMSSOption = TcpOptionMaximumSegmentSize.maybeMSS(tcpHeader)
        assert(nullMSSOption == mssOption)
    }

    @Test
    fun getWithMSSOption() {
        val mss: UShort = 1440u
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TcpOptionMaximumSegmentSize(mss = mss),
                    ),
            )
        val mssOption = TcpOptionMaximumSegmentSize.maybeMSS(tcpHeader)
        assertEquals(mssOption!!.mss, mss)
    }

    @Test
    fun getWithMSSOptionAmongOtherOptions() {
        val mss: UShort = 1440u
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TcpOptionEndOfOptionList(),
                        TcpOptionMaximumSegmentSize(mss = mss),
                        TcpOptionUnsupported(
                            0x03u,
                            byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08),
                        ),
                    ),
            )
        val mssOption = TcpOptionMaximumSegmentSize.maybeMSS(tcpHeader)
        assertEquals(mssOption!!.mss, mss)
    }

    @Test
    fun optionsToAndFromBuffer() {
        val mss: UShort = 1440u
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TcpOptionMaximumSegmentSize(mss = mss),
                        TcpOptionUnsupported(
                            0x03u,
                            byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08),
                        ),
                        TcpOptionTimestamp(tsval = 1u, tsecr = 2u),
                        TcpOptionNoOperation(),
                        TcpOptionEndOfOptionList(),
                    ),
            )

        val buffer = ByteBuffer.wrap(tcpHeader.toByteArray())
        val dump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer: \n$dump")
        val tcpHeaderFromBuffer = TcpHeader.fromStream(buffer)

        assertEquals(tcpHeader, tcpHeaderFromBuffer)
    }

    @Test
    fun endOfOptionListToString() {
        val endOfOptionList = TcpOptionEndOfOptionList()
        assertEquals("TCPOptionEndOfOptionList(kind=0 size=1)", endOfOptionList.toString())
    }

    @Test
    fun optionMssTooShort() {
        val options = arrayListOf(TcpOptionMaximumSegmentSize(1222u))
        val stream = ByteBuffer.allocate(options.sumOf { it.size.toInt() })
        for (option in options) {
            stream.put(option.toByteArray())
        }
        stream.rewind()
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            parseOptions(stream, stream.limit())
        }
    }

    @Test
    fun timeStampsShort() {
        val options = arrayListOf(TcpOptionTimestamp(1000u, 2000u))
        val stream = ByteBuffer.allocate(options.sumOf { it.size.toInt() })
        for (option in options) {
            stream.put(option.toByteArray())
        }
        stream.rewind()
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            parseOptions(stream, stream.limit())
        }
    }

    @Test
    fun unsupportedTooShortForLength() {
        val options = arrayListOf(TcpOptionUnsupported(kind = 88u, ByteArray(0)))
        val stream = ByteBuffer.allocate(options.sumOf { it.size.toInt() })
        for (option in options) {
            stream.put(option.toByteArray())
        }
        stream.rewind()
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            parseOptions(stream, stream.limit())
        }
    }

    @Test
    fun unsupportedToShortToGetFullLength() {
        val options = arrayListOf(TcpOptionUnsupported(kind = 88u, ByteArray(1)))
        val stream = ByteBuffer.allocate(options.sumOf { it.size.toInt() })
        for (option in options) {
            stream.put(option.toByteArray())
        }
        stream.rewind()
        stream.limit(stream.limit() - 1)
        assertThrows<PacketTooShortException> {
            parseOptions(stream, stream.limit())
        }
    }

    @Test
    fun optionsToAndFromBufferWithChecksum() {
        val mss: UShort = 1440u

        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678.toUInt(),
                acknowledgementNumber = 0x87654321.toUInt(),
                options =
                    arrayListOf(
                        TcpOptionMaximumSegmentSize(mss = mss),
                        TcpOptionUnsupported(
                            0x03u,
                            byteArrayOf(0x01),
                        ),
                        TcpOptionEndOfOptionList(),
                    ),
            )
        tcpHeader.setSyn(true)
        tcpHeader.setAck(true)
        val address = InetAddress.getLoopbackAddress()
        val ipHeader = IpHeader.createIPHeader(address, address, IpType.TCP, tcpHeader.getHeaderLength().toInt())
        // tcpHeader.checksum = TransportHeaderFactoryImpl.computeChecksum(ipHeader, tcpHeader, ByteBuffer.allocate(0))

        val buffer = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
        buffer.put(ipHeader.toByteArray())
        buffer.put(tcpHeader.toByteArray())
        buffer.rewind()
        val dump = stringPacketDumper.dumpBufferToString(buffer, 0, buffer.limit(), true)
        logger.debug("Buffer: \n$dump")
        val ipHeaderFromBuffer = IpHeader.fromStream(buffer)
        val tcpHeaderFromBuffer = NextHeader.fromStream(buffer, ipHeaderFromBuffer.protocol)

        assertEquals(ipHeader, ipHeaderFromBuffer)
        assertEquals(tcpHeader, tcpHeaderFromBuffer)
    }

    // really tests the updateDataOffsetAndNs() function
    @Test
    fun tcpHeaderTestEmptyOptions() {
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678u,
                acknowledgementNumber = 0x87654321u,
            )
        assertEquals(tcpHeader.getDataOffset(), TcpHeader.OFFSET_MIN)

        // add a NOP option to make sure that the data offset is calculated correctly after it was
        // there were no options and we add one
        // the NOP option is a size of 1 byte, so the data offset should be 1 32-bit word longer
        // because of zero padding
        tcpHeader.addOption(TcpOptionNoOperation())
        assertEquals(tcpHeader.getDataOffset(), (TcpHeader.OFFSET_MIN + 1u).toUByte())
    }

    // really tests the updateDataOffsetAndNs() function
    @Test
    fun tcpHeaderTestNonEmptyOptions() {
        val tcpHeader =
            TcpHeader(
                sourcePort = 1234u,
                destinationPort = 5678u,
                sequenceNumber = 0x12345678u,
                acknowledgementNumber = 0x87654321u,
                options =
                    arrayListOf(
                        TcpOptionNoOperation(),
                    ),
            )
        // make sure we start with a correct data offset
        assertEquals(tcpHeader.getDataOffset(), (TcpHeader.OFFSET_MIN + 1u).toUByte())

        // clear the options
        tcpHeader.clearOptions()
        assertEquals(tcpHeader.getDataOffset(), TcpHeader.OFFSET_MIN)
    }

    @Test
    fun parseOptionsNoOptions() {
        val buffer = ByteBuffer.allocate(0)
        val options = parseOptions(buffer, buffer.limit())
        assertTrue(options.isEmpty())
    }

    @Test
    fun parseOptionsOneOption() {
        val buffer = ByteBuffer.allocate(1)
        buffer.put(0x0) // end of options list
        buffer.rewind()

        val options = parseOptions(buffer, buffer.limit())
        assertEquals(1, options.size)
        assertTrue(options[0] is TcpOptionEndOfOptionList)
    }

    @Test
    fun parseOptionsTwoOptions() {
        val buffer = ByteBuffer.allocate(8)
        buffer.put(0x2) // maximum segment size
        buffer.put(0x4) // length
        buffer.putShort(1440u.toShort())
        buffer.put(0x0) // end of options list
        buffer.rewind()

        val options = parseOptions(buffer, buffer.limit())
        assertEquals(2, options.size)
        assertTrue(options[0] is TcpOptionMaximumSegmentSize)
        assertTrue(options[1] is TcpOptionEndOfOptionList)
    }

    @Disabled("Until we re-write the equals funciton on TcpHeader to discard padding options")
    @Test
    fun serializeDeserializeAllOptions() {
        val options =
            arrayListOf<TcpOption>(
                TcpOptionMaximumSegmentSize(1000u),
                TcpOptionTimestamp(1u, 2u),
                // TcpOptionUnsupported(88u, ByteArray(0)),
                // TcpOptionNoOperation(),
                // TcpOptionEndOfOptionList()
            )
        val tcpHeader = TcpHeader(options = options)
        val stream = ByteBuffer.wrap(tcpHeader.toByteArray())
        val parsedHeader = TcpHeader.fromStream(stream)
        assertEquals(tcpHeader, parsedHeader)
    }

    @Test
    fun testMaybeTimeStamp() {
        val tcpHeader = TcpHeader()
        assertNull(TcpOptionTimestamp.maybeTimestamp(tcpHeader))

        val timestamp = TcpOptionTimestamp(tsval = 1u, tsecr = 2u)
        val tcpHeader2 = TcpHeader(options = arrayListOf(TcpOptionMaximumSegmentSize(1000u), timestamp))
        assertNotNull(TcpOptionTimestamp.maybeTimestamp(tcpHeader2))
        assertEquals(timestamp, TcpOptionTimestamp.maybeTimestamp(tcpHeader2))
        assertEquals(timestamp.tsecr, TcpOptionTimestamp.maybeTimestamp(tcpHeader2)!!.tsecr)
        assertEquals(timestamp.tsval, TcpOptionTimestamp.maybeTimestamp(tcpHeader2)!!.tsval)

        // just here to increase line coverage with setters
        timestamp.tsecr = 3u
        timestamp.tsval = 4u
    }

    @Test
    fun tcpOptionUnsupportedEquals() {
        val option1 = TcpOptionUnsupported(88u, ByteArray(0))
        val option2 = TcpOptionUnsupported(88u, ByteArray(0))
        assertEquals(option1, option2)

        val option3 = TcpOptionUnsupported(88u, ByteArray(1))
        assertNotEquals(option1, option3)

        val option4 = TcpOptionNoOperation()
        assertNotEquals(option1, option4)

        val option5 = Ipv4OptionNoOperation()
        assertNotEquals(option1, option5)

        val option6 = TcpOptionUnsupported(88u, byteArrayOf(0x01))
        val option7 = TcpOptionUnsupported(88u, byteArrayOf(0x02))
        assertNotEquals(option6, option7)

        val option8 = TcpOptionUnsupported(89u, byteArrayOf(0x01))
        assertNotEquals(option6, option8)

        assertEquals(option7.kind, option6.kind)
        assertNotEquals(option7.data, option6.data)
    }

    @Test
    fun tcpOptionUnsupportedHashCode() {
        val map: MutableMap<TcpOptionUnsupported, String> = mutableMapOf()
        val option = TcpOptionUnsupported(88u, ByteArray(0))
        map[option] = "test"
        assertTrue(map.containsKey(option))
    }

    @Test
    fun tcpOptionUnsupportedToString() {
        val option = TcpOptionUnsupported(88u, ByteArray(0))
        assertEquals("TCPOptionUnsupported(Unknown, kind=88, size=2, data=[])", option.toString())

        val option2 = TcpOptionUnsupported(1u, ByteArray(0))
        assertEquals("TCPOptionUnsupported(NoOperation, kind=1, size=2, data=[])", option2.toString())
    }

    @Test
    fun tcpMssOrDefault() {
        val tcpHeader = TcpHeader()
        assertEquals(TcpOptionMaximumSegmentSize.mssOrDefault(tcpHeader), TcpOptionMaximumSegmentSize.defaultIpv4MSS)
        assertEquals(TcpOptionMaximumSegmentSize.mssOrDefault(tcpHeader, false), TcpOptionMaximumSegmentSize.defaultIpv6MSS)

        val mss = TcpOptionMaximumSegmentSize(1000u)
        val tcpHeader2 = TcpHeader(options = arrayListOf(mss))
        assertEquals(1000u.toUShort(), TcpOptionMaximumSegmentSize.mssOrDefault(tcpHeader2))
    }

    @Test fun tcpMSSToString() {
        val mss = TcpOptionMaximumSegmentSize(1000u)
        assertEquals("TCPOptionMaximumSegmentSize(kind=2 size=4 mss=1000)", mss.toString())
    }
}
