package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType

data class Ipv6HopByHopOption(
    override val nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = 0u,
    override val data: ByteArray = ByteArray(0),
) : Ipv6ExtensionHeader(nextHeader, length, data) {
    companion object {
        private val logger = org.slf4j.LoggerFactory.getLogger(Ipv6HopByHopOption::class.java)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ipv6HopByHopOption

        if (nextHeader != other.nextHeader) return false
        if (length != other.length) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nextHeader.hashCode()
        result = 31 * result + length.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
