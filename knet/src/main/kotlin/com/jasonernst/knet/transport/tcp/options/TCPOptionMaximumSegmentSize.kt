package com.jasonernst.knet.transport.tcp.options

import com.jasonernst.knet.transport.tcp.TCPHeader
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 3.7.1.  Maximum Segment Size Option
 *
 *    TCP endpoints MUST implement both sending and receiving the MSS
 *    Option (MUST-14).
 *
 *    TCP implementations SHOULD send an MSS Option in every SYN segment
 *    when its receive MSS differs from the default 536 for IPv4 or 1220
 *    for IPv6 (SHLD-5), and MAY send it always (MAY-3).
 *
 *    If an MSS Option is not received at connection setup, TCP
 *    implementations MUST assume a default send MSS of 536 (576 - 40) for
 *    IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
 *
 *    The maximum size of a segment that a TCP endpoint really sends, the
 *    "effective send MSS", MUST be the smaller (MUST-16) of the send MSS
 *    (that reflects the available reassembly buffer size at the remote
 *    host, the EMTU_R [19]) and the largest transmission size permitted by
 *    the IP layer (EMTU_S [19]):
 *
 *    Eff.snd.MSS = min(SendMSS+20, MMS_S) - TCPhdrsize - IPoptionsize
 *
 *    where:
 *
 *    *  SendMSS is the MSS value received from the remote host, or the
 *       default 536 for IPv4 or 1220 for IPv6, if no MSS Option is
 *       received.
 *
 *    *  MMS_S is the maximum size for a transport-layer message that TCP
 *       may send.
 *
 *    *  TCPhdrsize is the size of the fixed TCP header and any options.
 *       This is 20 in the (rare) case that no options are present but may
 *       be larger if TCP Options are to be sent.  Note that some options
 *       might not be included on all segments, but that for each segment
 *       sent, the sender should adjust the data length accordingly, within
 *       the Eff.snd.MSS.
 *
 *    *  IPoptionsize is the size of any IPv4 options or IPv6 extension
 *       headers associated with a TCP connection.  Note that some options
 *       or extension headers might not be included on all packets, but
 *       that for each segment sent, the sender should adjust the data
 *       length accordingly, within the Eff.snd.MSS.
 *
 *    The MSS value to be sent in an MSS Option should be equal to the
 *    effective MTU minus the fixed IP and TCP headers.  By ignoring both
 *    IP and TCP Options when calculating the value for the MSS Option, if
 *    there are any IP or TCP Options to be sent in a packet, then the
 *    sender must decrease the size of the TCP data accordingly.  RFC 6691
 *    [43] discusses this in greater detail.
 *
 *    The MSS value to be sent in an MSS Option must be less than or equal
 *    to:
 *
 *       MMS_R - 20
 *
 *    where MMS_R is the maximum size for a transport-layer message that
 *    can be received (and reassembled at the IP layer) (MUST-67).  TCP
 *    obtains MMS_R and MMS_S from the IP layer; see the generic call
 *    GET_MAXSIZES in Section 3.4 of RFC 1122.  These are defined in terms
 *    of their IP MTU equivalents, EMTU_R and EMTU_S [19].
 *
 *    When TCP is used in a situation where either the IP or TCP headers
 *    are not fixed, the sender must reduce the amount of TCP data in any
 *    given packet by the number of octets used by the IP and TCP options.
 *    This has been a point of confusion historically, as explained in RFC
 *    6691, Section 3.1.
 */
data class TCPOptionMaximumSegmentSize(
    val mss: UShort,
) : TCPOption(type = TCPOptionTypeSupported.MaximumSegmentSize, size = (BASE_OPTION_SIZE + 2).toUByte()) {
    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(size.toInt())
        buffer.put(super.toByteArray(order))
        buffer.putShort(mss.toShort())
        return buffer.array()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(TCPOptionMaximumSegmentSize::class.java)

        // note: we use the IPv4 max header length because it is 60, whereas the IPv6 header length
        // is 40. We are leaving some bytes on the table in the case where the IPv4 header doesn't
        // have options present or when using IPv6, but this is much more simple.
        val defaultIpv4MSS: UShort = 536u
        val defaultIpv6MSS: UShort = 1220u

        fun maybeMSS(tcpHeader: TCPHeader): TCPOptionMaximumSegmentSize? =
            tcpHeader.getOptions().find { it.type == TCPOptionTypeSupported.MaximumSegmentSize }
                as TCPOptionMaximumSegmentSize?

        fun mssOrDefault(
            tcpHeader: TCPHeader,
            ipv4: Boolean = true,
        ): UShort {
            val mss = maybeMSS(tcpHeader)
            if (mss != null) {
                return mss.mss
            }
            logger.warn("No MSS option found in TCP header, using default")
            return if (ipv4) defaultIpv4MSS else defaultIpv6MSS
        }
    }

    override fun toString(): String = "TCPOptionMaximumSegmentSize(kind=${type.kind} size=$size mss=$mss)"
}
