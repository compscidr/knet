package com.jasonernst.knet.application.dns

import com.jasonernst.knet.application.dns.DnsMessage.Companion.MAX_UDP_SIZE
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.StandardProtocolFamily
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.spi.AbstractSelectableChannel

/**
 * Tests out the DNSMessage class.
 * - Verify to and from buffers is working
 * - Verify a real server can understand requests and response to them.
 */
@Timeout(10)
class DnsTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val stringPacketDumper = StringPacketDumper()

    @Test
    fun testDnsMessage() {
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))

        // serialize
        val stream = ByteBuffer.wrap(dnsMessage.toByteArray())
        // deserialize
        val dnsMessage2 = DnsMessage.fromStream(stream)

        assertEquals(dnsMessage, dnsMessage2)
    }

    @Test
    fun dnsOverUDP() {
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = ByteBuffer.wrap(dnsMessage.toByteArray())

        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)
        val udpPacket = DatagramPacket(dnsMessage.toByteArray(), dnsMessage.toByteArray().size, dnsServer)

        // ensure we get an ipv4 socket for sure on systems that may default to ipv6
        val socket = DatagramChannel.open(StandardProtocolFamily.INET).socket()
        socket.send(udpPacket)

        val dnsMessageBufferHexdump = stringPacketDumper.dumpBufferToString(dnsMessageBuffer, 0, dnsMessageBuffer.limit())
        logger.debug("DNS Request: \n$dnsMessageBufferHexdump")

        val responseArray = ByteArray(MAX_UDP_SIZE)
        val responsePacket = DatagramPacket(responseArray, responseArray.size)
        socket.receive(responsePacket)
        val responseBuffer = ByteBuffer.wrap(responseArray)
        responseBuffer.limit(responsePacket.length)
        logger.debug("Received response from DNS server: ${responsePacket.address} of size ${responsePacket.length}")
        val dnsResponseHexDump = stringPacketDumper.dumpBufferToString(responseBuffer, 0, responseBuffer.limit())
        logger.debug("DNS Response: \n$dnsResponseHexDump")
        val receivedMessage = DnsMessage.fromStream(responseBuffer)
        logger.debug("Parsed message: $receivedMessage")
        assertEquals(0u.toUByte(), receivedMessage.header.rcode)
    }

    /**
     * Was having an issue with DNSResponses being corrupted when using non-blocking UDP. This test
     * should confirm whether there is a bug in our code, or if it is caused by the non-blocking
     * UDP itself.
     */
    @Test
    fun dnsOverNonBlockingUDP() {
        val selector: Selector = Selector.open()
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = ByteBuffer.wrap(dnsMessage.toByteArray())

        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)

        val channel = DatagramChannel.open()
        channel.configureBlocking(false)
        channel.socket().soTimeout = 0
        channel.connect(dnsServer)
        channel.send(dnsMessageBuffer, dnsServer)

        val dnsMessageBufferHexdump = stringPacketDumper.dumpBufferToString(dnsMessageBuffer, 0, dnsMessageBuffer.limit())
        logger.debug("DNS Request: \n$dnsMessageBufferHexdump")

        channel.register(selector, SelectionKey.OP_READ)
        selector.select()
        val responseBuffer = ByteBuffer.allocate(MAX_UDP_SIZE)
        for (key: SelectionKey in selector.selectedKeys()) {
            if (key.isReadable) {
                val bytesRead = channel.read(responseBuffer)
                if (bytesRead > 0) {
                    logger.debug("Received $bytesRead bytes from DNS server: ${channel.remoteAddress}")

                    val dnsResponseHexDump = stringPacketDumper.dumpBufferToString(responseBuffer, 0, responseBuffer.limit())
                    logger.debug("DNS Response: \n$dnsResponseHexDump")
                    val parsedMessage = DnsMessage.fromStream(responseBuffer)
                    logger.debug("PARSED MESSAGE: $parsedMessage")
                    assertEquals(0u.toUByte(), parsedMessage.header.rcode)
                } else {
                    logger.debug("No bytes read")
                }
            }
        }
        selector.close()
    }

    /**
     * Was having an issue with DNSResponses being corrupted when using non-blocking UDP.
     *
     * This is similar to the non-blocking test, but uses some of the casting that is being done
     * in the our codebase, to make sure none of that is affecting anything.
     *
     * This test should confirm whether there is a bug in our code, or if it is caused by the
     * non-blocking UDP itself.
     */
    @Test
    fun dnsOverNonBlockingUDPWithByteChannel() {
        val selector: Selector = Selector.open()
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = ByteBuffer.wrap(dnsMessage.toByteArray())

        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)

        val channel = DatagramChannel.open()
        channel.configureBlocking(false)
        channel.socket().soTimeout = 0
        channel.connect(dnsServer)

        val byteChannel = channel as ByteChannel
        byteChannel.write(dnsMessageBuffer)

        val dump = stringPacketDumper.dumpBufferToString(dnsMessageBuffer, 0, dnsMessageBuffer.limit())
        logger.debug("DNS Request: \n$dump")

        val abstractChannel = channel as AbstractSelectableChannel

        val selectionKey = abstractChannel.register(selector, SelectionKey.OP_READ)
        selectionKey.interestOps(selectionKey.interestOps() or SelectionKey.OP_WRITE)
        selector.select()
        val responseBuffer = ByteBuffer.allocate(MAX_UDP_SIZE)
        for (key: SelectionKey in selector.selectedKeys()) {
            if (key.isReadable) {
                val bytesRead = byteChannel.read(responseBuffer)
                if (bytesRead > 0) {
                    logger.debug("Received $bytesRead bytes from DNS server: ${channel.remoteAddress}")
                    val dump = stringPacketDumper.dumpBufferToString(responseBuffer, 0, responseBuffer.limit())
                    logger.debug("DNS Response: \n$dump")
                    responseBuffer.rewind()
                    val response = DnsMessage.fromStream(responseBuffer)
                    logger.debug("RESPONSE: $response")
                    assertEquals(0u, response.header.rcode.toUInt())
                } else {
                    logger.debug("No bytes read")
                }
            }
        }
        selector.close()
    }

    @Test
    fun dnsOverTCP() {
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = ByteBuffer.wrap(dnsMessage.toByteArray())
        val dump = stringPacketDumper.dumpBufferToString(dnsMessageBuffer, 0, dnsMessageBuffer.limit())
        logger.debug("DNS Request: \n$dump")

        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)

        val dnsConnection = Socket()
        dnsConnection.connect(dnsServer)

        val outputStream = dnsConnection.getOutputStream()
        outputStream.write(dnsMessage.toByteArray())
        outputStream.flush()

        val inputStream = dnsConnection.getInputStream()
        val responseBuffer = ByteArray(MAX_UDP_SIZE)

        val bytesRead = inputStream.read(responseBuffer)
        logger.debug(
            "Received response from DNS server: {} of size {}",
            dnsConnection.remoteSocketAddress,
            bytesRead,
        )

        // todo finish these tests:
        //  https://linear.app/bumpapp/issue/BUMP-760/secure-dns-over-tcp
        //  https://linear.app/bumpapp/issue/BUMP-758/dns-over-tcp
        //  https://linear.app/bumpapp/issue/BUMP-759/dns-over-ipv6
    }
}
