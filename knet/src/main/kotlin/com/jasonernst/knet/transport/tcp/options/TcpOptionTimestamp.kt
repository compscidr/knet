package com.jasonernst.knet.transport.tcp.options

import com.jasonernst.knet.transport.tcp.TcpHeader
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Represents the TCP Timestamp option. See RFC 7323 for more information.
 * https://www.rfc-editor.org/rfc/rfc7323.txt
 */
data class TcpOptionTimestamp(
    var tsval: UInt,
    var tsecr: UInt,
) : TcpOption(type = TcpOptionTypeSupported.Timestamps, size = (BASE_OPTION_SIZE + 8).toUByte()) {
    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(size.toInt())
        buffer.put(super.toByteArray(order))
        buffer.putInt(tsval.toInt())
        buffer.putInt(tsecr.toInt())
        return buffer.array()
    }

    companion object {
        fun maybeTimestamp(tcpHeader: TcpHeader): TcpOptionTimestamp? =
            tcpHeader.getOptions().find { it.type == TcpOptionTypeSupported.Timestamps }
                as TcpOptionTimestamp?
    }
}
