package com.jasonernst.knet.ip

data class IPv6HopByHopOption(
    override val nextHeader: UByte = IPType.TCP.value,
    override val length: UByte = 0u,
    override val data: ByteArray = ByteArray(0),
) : IPv6ExtensionHeader(nextHeader, length, data) {
    companion object {
        private val logger = org.slf4j.LoggerFactory.getLogger(IPv6HopByHopOption::class.java)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IPv6HopByHopOption

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
