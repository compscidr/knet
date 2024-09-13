package com.jasonernst.knet.ip.options

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class Ipv4OptionUnknown(
    override val isCopied: Boolean,
    override val optionClass: Ipv4OptionClassType,
    override val type: Ipv4OptionType,
    override val size: UByte,
    val data: ByteArray,
) : Ipv4Option(isCopied, optionClass, type, size) {
    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(2 + data.size)
        buffer.put(super.toByteArray(order)) // get the type byte sorted out
        buffer.put(size.toByte())
        buffer.put(data)
        return buffer.array()
    }
}
