package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer

/**
 * https://datatracker.ietf.org/doc/html/rfc4302
 */
class Ipv6Authentication(
    override var nextHeader: UByte,
    override val length: UByte = 0u,
) : Ipv6ExtensionHeader(IpType.AH, nextHeader = nextHeader, length = length) {
    companion object {
        // nextheader, length, reserved, SPI, sequence number, ICV
        const val MIN_LENGTH = 20

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6Authentication = Ipv6Authentication(nextheader, length)
    }
}
