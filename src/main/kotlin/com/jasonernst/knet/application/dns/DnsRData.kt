package com.jasonernst.knet.application.dns

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import java.nio.ByteBuffer
import java.nio.ByteOrder

open class DnsRData(
    private var data: ByteArray,
) {
    private val stringPacketDumper = StringPacketDumper()

    init {
        setData(data)
    }

    companion object {
        fun fromStream(
            stream: ByteBuffer,
            qType: DnsType,
        ): DnsRData {
            if (stream.remaining() < 2) {
                throw PacketTooShortException("Not enough bytes to determine DNSRecord RDATA length, need 2, have ${stream.remaining()}")
            }
            val rdLength = stream.short.toUShort()
            if (stream.remaining() < rdLength.toInt()) {
                throw PacketTooShortException(
                    "Not enough bytes to parse DNSRecord RDATA need at least $rdLength more, have ${stream.remaining()}",
                )
            }

            // specific type
            if (qType == DnsType.A) {
                return DnsARData.fromStream(stream)
            }

            // otherwise, generic type
            val rDataBytes = ByteArray(rdLength.toInt())
            stream.get(rDataBytes)
            return DnsRData(rDataBytes)
        }
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

    override fun toString(): String = "DnsRData(data=${stringPacketDumper.dumpBufferToString(ByteBuffer.wrap(data))})"
}
