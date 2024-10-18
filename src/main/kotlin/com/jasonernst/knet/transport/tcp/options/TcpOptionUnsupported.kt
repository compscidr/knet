package com.jasonernst.knet.transport.tcp.options

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class TcpOptionUnsupported(
    val kind: UByte,
    val data: ByteArray,
) : TcpOption(
        type =
            try {
                TcpOptionTypeSupported.fromKind(kind)
            } catch (e: NoSuchElementException) {
                TcpOptionTypeSupported.Unsupported
            },
        size = (BASE_OPTION_SIZE + data.size).toUByte(),
    ) {
    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(size.toInt())
        buffer.put(super.toByteArray(order))
        buffer.put(data)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TcpOptionUnsupported

        if (kind != other.kind) return false
        if (size != other.size) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = kind.hashCode()
        result = 31 * result + size.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }

    override fun toString(): String {
        val kindString =
            try {
                TcpOptionTypeSupported.fromKind(kind).toString()
            } catch (e: NoSuchElementException) {
                "Unknown"
            }
        return "TCPOptionUnsupported($kindString, kind=$kind, size=$size, data=${data.contentToString()})"
    }
}
