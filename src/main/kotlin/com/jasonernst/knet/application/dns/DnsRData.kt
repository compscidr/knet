package com.jasonernst.knet.application.dns

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.properties.Delegates

class DnsRData(
    private var data: ByteArray,
) {
    private var length by Delegates.notNull<Short>()

    init {
        setData(data)
    }

    fun setData(data: ByteArray) {
        if (data.size > (UShort.MAX_VALUE - 1u).toInt()) {
            throw IllegalArgumentException("RData length must be less than ${UShort.MAX_VALUE - 1u}")
        }
        this.data = data
    }

    fun size(): Short = data.size.toShort()

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(data.size + 2) // extra 2 is for the length as a short
        buffer.order(order)
        buffer.putShort(data.size.toShort())
        buffer.put(data)
        return buffer.array()
    }
}
