package com.jasonernst.knet.transport.tcp

import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.packetCounter
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.DEFAULT_WINDOW_SIZE
import com.jasonernst.knet.transport.tcp.options.TcpOption
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.Random

object TcpHeaderFactory {
    /**
     * Performs a bunch of common steps regardless of the response:
     * 1. Copies the headers so we still have the originals
     * 2. Sets the Flags
     * 2. Sets the SEQ and ACK numbers
     * 3. optionally swaps source and dest addresses and ports
     * 4. computes the checksum
     * 5. returns the packet
     * @param ipHeader the IP header to base the response from
     * @param transportHeader the transport header to base the response from
     * @param seqNumber the sequence number to set in the response
     * @param ackNumber the acknowledgement number to set in the response
     * @param swapSourceAndDestination whether to swap the source and destination addresses and
     * ports
     * @param payload the payload to include in the response and use for checksum calculation
     *  can use ByteBuffer.allocate(0) if no payload
     *
     *  NB: at the end of this, the payload position is set to payload.limit()
     */
    fun prepareResponseHeaders(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
        swapSourceAndDestination: Boolean = true,
        payload: ByteBuffer = ByteBuffer.allocate(0),
        isSyn: Boolean = false,
        isAck: Boolean = false,
        isPsh: Boolean = false,
        isFin: Boolean = false,
        isRst: Boolean = false,
        isUrg: Boolean = false,
        windowSize: UShort = DEFAULT_WINDOW_SIZE,
        urgentPointer: UShort = 0u,
        options: List<TcpOption> = emptyList(),
    ): Packet {
        require(ipHeader.sourceAddress::class == ipHeader.destinationAddress::class) {
            "IP header source and destination addresses must be the same type"
        }

        // if we want to respond with different options this is the place to do it
        val responseTcpHeader =
            TcpHeader(
                sourcePort = tcpHeader.sourcePort,
                destinationPort = tcpHeader.destinationPort,
                sequenceNumber = seqNumber,
                acknowledgementNumber = ackNumber,
                windowSize = windowSize,
                urgentPointer = urgentPointer,
                options = options,
            )

        val payloadCopy = ByteArray(payload.remaining())
        payload.get(payloadCopy)

        responseTcpHeader.setSyn(isSyn)
        responseTcpHeader.setAck(isAck)
        responseTcpHeader.setPsh(isPsh)
        responseTcpHeader.setFin(isFin)
        responseTcpHeader.setRst(isRst)
        responseTcpHeader.setUrg(isUrg)

        val sourceAddress = if (swapSourceAndDestination) ipHeader.destinationAddress else ipHeader.sourceAddress
        val destinationAddress = if (swapSourceAndDestination) ipHeader.sourceAddress else ipHeader.destinationAddress

        val totalLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUInt()).toUShort()

        val responseIpHeader =
            when (sourceAddress) {
                is Inet4Address -> {
                    destinationAddress as Inet4Address
                    Ipv4Header(
                        id = packetCounter.getAndIncrement().toUShort(),
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = ipHeader.protocol,
                        totalLength = totalLength,
                    )
                }

                is Inet6Address -> {
                    destinationAddress as Inet6Address
                    Ipv6Header(
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = ipHeader.protocol,
                        payloadLength = totalLength,
                    )
                }

                else -> {
                    throw IllegalArgumentException("Unknown IP address type")
                }
            }
        responseTcpHeader.checksum = responseTcpHeader.computeChecksum(responseIpHeader, payloadCopy)
        return Packet(responseIpHeader, responseTcpHeader, payloadCopy)
    }

    /**
     * Given a TCP packet, create an ACK packet with the given ackNumber of how many bytes we
     * are acknowledging we have received.
     *
     * Note: we don't just look at the previous TCP header to determine the ackNumber because it
     * depends on how many bytes we are acknowledging we have received (computed by a TCP state machine
     * or something that is out of the scope of this library).
     *
     * Similarly, the sequence number we send back depends on the current state of the TCP state machine and isn't
     * always based on the ACK number of the previous packet.
     *
     * @param ipHeader the IP header of the packet we are responding to
     * @param tcpHeader the TCP header of the packet we are responding to
     * @param seqNumber the sequence number to use in the response
     * @param ackNumber the acknowledgement number to use in the response
     * @param payload the payload to attach to the ACK (may be empty)
     */
    fun createAckPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
        payload: ByteBuffer = ByteBuffer.allocate(0),
        isPsh: Boolean = false,
        windowSize: UShort = DEFAULT_WINDOW_SIZE,
    ): Packet =
        prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            seqNumber,
            ackNumber,
            payload = payload,
            isAck = true,
            isPsh = isPsh,
            windowSize = windowSize,
        )

    /**
     * Given an ipHeader, tcpHeader, constructs a FIN packet with the given seq, ack numbers
     */
    fun createFinPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
    ): Packet =
        prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            seqNumber,
            ackNumber,
            isFin = true,
            isAck = true,
        )

    /**
     * Given the last received packet from the client, create an RST packet to reset the connection.
     *
     * This is typically for when something went wonky and we need the other side to start again.
     *
     * Note the seq number must be the next expected seq number for the client based on the last
     * packet, or it won't take effect: https://www.rfc-editor.org/rfc/rfc5961#section-3.2
     *
     * This is because there is an attack where you could force resets without this.
     */
    fun createRstPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Packet {
        // page 36: RFC 793 https://datatracker.ietf.org/doc/html/rfc793#section-3.2
        // If the incoming segment has an ACK field, the reset takes its
        //    sequence number from the ACK field of the segment, otherwise the
        //    reset has sequence number zero and the ACK field is set to the sum
        //    of the sequence number and segment length of the incoming segment.
        //    The connection remains in the CLOSED state.
        val ackNumber: UInt
        val seqNumber: UInt

        // see page 64
        if (tcpHeader.isAck()) {
            seqNumber = tcpHeader.acknowledgementNumber
            ackNumber = 0u
        } else {
            seqNumber = 0u
            ackNumber = tcpHeader.sequenceNumber + ipHeader.getPayloadLength().toUInt() -
                tcpHeader.getHeaderLength().toUInt()
        }

        return prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            seqNumber,
            ackNumber,
            swapSourceAndDestination = true,
            isRst = true,
        )
    }

    /**
     * This is only used for tests, the OS creates the SYN packets, not us.
     *
     * NB: the source and destination should not be swapped when we create the SYN packet since
     * we are providing a previous packet from the other side to copy from.
     *
     * Technically the SYN packet supports payloads, but we don't use them here.
     *
     * @param sourceAddress the source address of the SYN packet
     * @param destinationAddress the destination address of the SYN packet
     * @param sourcePort the source port of the SYN packet
     * @param destinationPort the destinationPort
     * @param startingSeq the sequence number to start the TCP session with
     */
    fun createSynPacket(
        sourceAddress: InetAddress,
        destinationAddress: InetAddress,
        sourcePort: UShort,
        destinationPort: UShort,
        startingSeq: UInt,
        mss: UShort,
    ): Packet {
        val tcpHeader = TcpHeader(sourcePort, destinationPort, startingSeq, 0u)
        val tcpOptions = listOf(TcpOptionMaximumSegmentSize(mss), TcpOptionEndOfOptionList())

        val ipHeader =
            IpHeader.createIPHeader(
                sourceAddress,
                destinationAddress,
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt(),
            )

        return prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            startingSeq,
            0u,
            swapSourceAndDestination = false,
            isSyn = true,
            options = tcpOptions,
        )
    }

    /**
     * Given a SYN packet, create a SYN-ACK packet to send back to the client. Note the IP and TCP
     * source / destination returned will be returned swapped from those sent to this function.
     *
     * The sequence number will be randomly generated. The acknowledgement number will be the the
     * previously received sequence number + 1
     * (see https://datatracker.ietf.org/doc/html/rfc793#section-3.2)
     *
     * NB: While TCP supports sending data in the SYN packet, we do not for now.
     *
     * @param ipHeader the IP header of the SYN packet
     * @param tcpHeader the TCP header of the SYN packet
     *
     * @return A Packet with the SYN-ACK packet encapsulated in the IP and TCP headers
     */
    fun createSynAckPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        mss: UShort,
    ): Packet {
        require(tcpHeader.isSyn()) { "Cannot create SYN-ACK packet for non-SYN packet" }
        val tcpOptions = listOf(TcpOptionMaximumSegmentSize(mss), TcpOptionEndOfOptionList())
        // use a random sequence number because we're just starting the session
        // todo: probably update this to not be random using this approach:
        //   pg: 27 https://datatracker.ietf.org/doc/html/rfc793
        // To avoid confusion we must prevent segments from one incarnation of a
        //  connection from being used while the same sequence numbers may still
        //  be present in the network from an earlier incarnation.  We want to
        //  assure this, even if a TCP crashes and loses all knowledge of the
        //  sequence numbers it has been using.  When new connections are created,
        //  an initial sequence number (ISN) generator is employed which selects a
        //  new 32 bit ISN.  The generator is bound to a (possibly fictitious) 32
        //  bit clock whose low order bit is incremented roughly every 4
        //  microseconds.  Thus, the ISN cycles approximately every 4.55 hours.
        //  Since we assume that segments will stay in the network no more than
        //  the Maximum Segment Lifetime (MSL) and that the MSL is less than 4.55
        //  hours we can reasonably assume that ISN's will be unique.
        return prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            Random().nextInt().toUInt(),
            tcpHeader.sequenceNumber + 1u,
            true,
            ByteBuffer.allocate(0),
            true,
            true,
            false,
            false,
            options = tcpOptions,
        )
    }
}
