package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://datatracker.ietf.org/doc/html/rfc4303
 */
class Ipv6EncapsulatingSecurityPayload(
    val securityParametersIndex: UInt,
    val sequenceNumber: UInt,
    override var nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
) : Ipv6ExtensionHeader(IpType.ESP, nextHeader = nextHeader, length = length) {
    companion object {
        fun fromStream(
            stream: ByteBuffer,
            nextHeader: UByte,
            length: UByte,
        ): Ipv6EncapsulatingSecurityPayload {
            TODO()
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        TODO()
    }
}
