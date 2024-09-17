package com.jasonernst.knet.ip.options

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class Ipv4OptionUnknown(
    override val isCopied: Boolean = true,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.Unknown,
    override val size: UByte = MINIMUM_SIZE,
    val data: ByteArray = ByteArray(0),
) : Ipv4Option(isCopied, optionClass, type, size) {
    companion object {
        val MINIMUM_SIZE: UByte = 2u // 1 byte for type, 1 byte for size
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MINIMUM_SIZE.toInt() + data.size)
        buffer.put(super.toByteArray(order)) // get the type byte sorted out
        buffer.put(data)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ipv4OptionUnknown

        if (isCopied != other.isCopied) return false
        if (optionClass != other.optionClass) return false
        if (type != other.type) return false
        if (size != other.size) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isCopied.hashCode()
        result = 31 * result + optionClass.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + size.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
