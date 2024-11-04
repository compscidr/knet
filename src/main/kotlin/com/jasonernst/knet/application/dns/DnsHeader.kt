package com.jasonernst.knet.application.dns

import com.jasonernst.knet.PacketTooShortException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
 */
data class DnsHeader(
    var id: UShort,
    var response: Boolean,
    var opcode: UByte,
    var aa: Boolean,
    var tc: Boolean,
    var rd: Boolean,
    var ra: Boolean,
    var rcode: UByte,
    var qdCount: UShort,
    var anCount: UShort,
    var nsCount: UShort,
    var arCount: UShort,
) {
    companion object {
        const val DNS_HEADER_LENGTH = 12

        fun fromStream(stream: ByteBuffer): DnsHeader {
            if (stream.remaining() < DNS_HEADER_LENGTH) {
                throw PacketTooShortException(
                    "Not enough bytes to parse a DNS header, need at least $DNS_HEADER_LENGTH, have ${stream.limit()}",
                )
            }

            val id = stream.short.toUShort()
            val qrByte = stream.get().toUByte()
            val qr: UInt = (qrByte.toUInt() shr 7) and 0x1u
            val opcode: UByte = ((qrByte.toUInt() shr 3) and 0xFu).toUByte()
            val aa: UInt = (qrByte and 0x4u).toUInt()
            val tc: UInt = (qrByte and 0x2u).toUInt()
            val rd: UInt = (qrByte and 0x1u).toUInt()

            val raByte = stream.get().toUByte()
            val ra = (raByte.toUInt() shr 7) and 0x1u
            val rCode = raByte and 0xFu

            val qdCount = stream.short.toUShort()
            val anCount = stream.short.toUShort()
            val nsCount = stream.short.toUShort()
            val arCount = stream.short.toUShort()

            return DnsHeader(
                id = id,
                response = qr == 1u,
                opcode = opcode,
                aa = aa == 1u,
                tc = tc == 1u,
                rd = rd == 1u,
                ra = ra == 1u,
                rcode = rCode,
                qdCount = qdCount,
                anCount = anCount,
                nsCount = nsCount,
                arCount = arCount,
            )
        }
    }

    fun size() = DNS_HEADER_LENGTH

    // helper fun to help serialization
    private fun Boolean.toInt() = if (this) 1 else 0

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(DNS_HEADER_LENGTH)
        buffer.order(order)
        buffer.putShort(id.toShort())

        var qrByte: UInt = (response.toInt() shl 7).toUInt()
        qrByte += (opcode.toUInt() shl 6)
        qrByte += (aa.toInt() shl 2).toUInt()
        qrByte += (tc.toInt() shl 1).toUInt()
        qrByte += (rd.toInt()).toUInt()
        check(qrByte < 256u) {
            "qrByte is greater than 256: $qrByte, response: ${response.toInt()}, opcode: " +
                "${opcode.toUInt()}, aa: ${aa.toInt()}, tc:${tc.toInt()}, rd: ${rd.toInt()}"
        }
        buffer.put(qrByte.toByte())

        var raByte: UInt = (ra.toInt() shl 7).toUInt()
        raByte += rcode.toUInt()
        check(raByte < 256u) {
            "raByte is greater than 256: $raByte, ra: ${ra.toInt()}," +
                " rcode: ${rcode.toInt()}"
        }
        buffer.put(raByte.toByte())

        buffer.putShort(qdCount.toShort())
        buffer.putShort(anCount.toShort())
        buffer.putShort(nsCount.toShort())
        buffer.putShort(arCount.toShort())

        return buffer.array()
    }
}
