package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://datatracker.ietf.org/doc/html/rfc4303
 */
class Ipv6EncapsulatingSecurityPayload(
    override val nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = MIN_LENGTH,
) : Ipv6ExtensionHeader(nextHeader = nextHeader, length = length) {
    companion object {
        const val MIN_LENGTH: UByte = 2u // next header and length with no actual option data

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
            length: UByte,
        ): Ipv6EncapsulatingSecurityPayload = Ipv6EncapsulatingSecurityPayload(nextheader, length)
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        return buffer.array()
    }
}
