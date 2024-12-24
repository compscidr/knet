package com.jasonernst.knet

import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.TransportHeader
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Encapsulates everything we need a for a full packet, an IP header, a set of next headers (usually
 * only a single next header if we have an IPv4 packet, but could be more if we have an IPv6 packet
 * with hop-by-hop options, for example).
 */
open class Packet(
    val ipHeader: IpHeader?,
    val nextHeaders: NextHeader?,
    val payload: ByteArray?,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        private val logger = LoggerFactory.getLogger(javaClass)

        /**
         * Parses a single packet from the stream. This will parse the IP header, the next header and the payload. If
         * the stream is too short to fully parse the packet, a [PacketTooShortException] will be thrown. The caller
         * is responsible for catching this exception and handling it appropriately. (it suggested that the caller
         * preserves the position before calling this function, and upon catching the exception, resets the position,
         * reads more data into the buffer, and tries again).
         */
        fun fromStream(stream: ByteBuffer): Packet {
            val ipHeader = IpHeader.fromStream(stream)
            val nextHeaderLimit = ipHeader.getTotalLength() - ipHeader.getHeaderLength()
            val nextHeader = NextHeader.fromStream(ipHeader, stream, nextHeaderLimit.toInt())
            val expectedRemaining = (ipHeader.getTotalLength() - ipHeader.getHeaderLength() - nextHeader.getHeaderLength()).toInt()
            if (stream.remaining() < expectedRemaining) {
                throw PacketTooShortException(
                    "Packet too short to obtain entire payload, have ${stream.remaining()}, expecting $expectedRemaining",
                )
            }
            if (expectedRemaining < 0) {
                logger.warn(
                    "Expected remaining is negative, something is wrong: {} IP total length: {} IP header length: {} next header length: {}",
                    expectedRemaining,
                    ipHeader.getTotalLength(),
                    ipHeader.getHeaderLength(),
                    nextHeader.getHeaderLength(),
                )
                return Packet(ipHeader, nextHeader, ByteArray(0))
            }
            val payload = ByteArray(expectedRemaining)
            stream.get(payload)
            return Packet(ipHeader, nextHeader, payload)
        }

        /**
         * This function will parse all packets in the stream. If the final packet is a partial packet, it will
         * be left in the stream for the next call to this function. The position of the stream will be set to just
         * after the partial packet, and the stream will be compacted so all of the fully parsed packets are removed
         * from the stream. The stream is ready to be written to again after this function is called.
         *
         * If a packet is really malformed, the stream will advance one byte at a time and try again to parse the
         * stream until it finds an acceptable packet again.
         *
         * The packets will be either IPv4 or Ipv6 headers, followed by NextHeader(s) which are typically
         * TCP, UDP, ICMP, etc. This is followed by the optional payload.
         *
         * For TCP packets, we need to make a request on behalf of the client on a protected TCP socket.
         * We then need to listen to the return traffic and send it back to the client, and ensure that
         * the sequence numbers are maintained etc.
         *
         * For UDP packets, we can just send them to the internet and listen for the return traffic and
         * then just send it back to the client.
         *
         * For ICMP, we need to use an ICMP socket (https://github.com/compscidr/icmp) to send the
         * request and listen for the return traffic. We then return the ICMP result to the client. This
         * may be unreachable, time exceeded, etc, or just a successful ping response.
         */
        fun parseStream(stream: ByteBuffer): List<Packet> {
            val packets = mutableListOf<Packet>()
            while (stream.hasRemaining()) {
                val position = stream.position()
                try {
                    val packet = fromStream(stream)
                    packets.add(packet)
                } catch (e: IllegalArgumentException) {
                    // don't bother to rewind the stream, just log and continue at position + 1
                    logger.error("Error parsing stream: ", e)
                    stream.position(position + 1)
                } catch (e: PacketTooShortException) {
                    logger.warn("Packet too short to parse, trying again when more data arrives: {}", e.message)
                    // logger.debug("POSITION: {} LIMIT: {}, RESETTING TO START: {}", stream.position(), stream.limit(), position)
                    // rewind the stream to before we tried parsing so we can try again later
                    stream.position(position)
                    break
                }
            }
            stream.compact()
            return packets
        }
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        if (ipHeader == null) {
            return ByteArray(0)
        }
        val buffer = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
        buffer.order(order)
        val ipHeaderBytes = ipHeader.toByteArray()
        buffer.put(ipHeaderBytes)

        if (nextHeaders is TransportHeader) {
            nextHeaders.checksum = nextHeaders.computeChecksum(ipHeader, payload ?: ByteArray(0))
        }
        val nextHeaderBytes = nextHeaders?.toByteArray()
        buffer.put(nextHeaderBytes)
        buffer.put(payload)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Packet

        if (ipHeader != other.ipHeader) return false
        if (nextHeaders != other.nextHeaders) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ipHeader.hashCode()
        result = 31 * result + nextHeaders.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    override fun toString(): String = "Packet(ipHeader=$ipHeader, nextHeaders=$nextHeaders, payloadSize=${payload?.size ?: 0})"
}
