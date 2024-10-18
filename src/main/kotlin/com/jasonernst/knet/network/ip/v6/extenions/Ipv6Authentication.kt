package com.jasonernst.knet.network.ip.v6.extenions

import com.jasonernst.knet.network.ip.IpType
import java.nio.ByteBuffer

/**
 * https://datatracker.ietf.org/doc/html/rfc4302
 */
class Ipv6Authentication(
    override var nextHeader: UByte,
    override val length: UByte = 0u,
) : Ipv6ExtensionHeader(IpType.AH, nextHeader = nextHeader, length = length) {
    companion object {
        fun fromStream(
            stream: ByteBuffer,
            nextHeader: UByte,
            length: UByte,
        ): Ipv6Authentication {
            TODO()
        }
    }
}
