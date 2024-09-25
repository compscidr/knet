package com.jasonernst.knet.ip.v6.extenions

import com.jasonernst.knet.ip.IpType
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.and

class Ipv6Fragment(
    override val nextHeader: UByte = IpType.TCP.value,
    override val length: UByte = MIN_LENGTH,
    val fragmentOffset: UShort = 0u,
    val moreFlag: Boolean = false,
    val identification: UInt = 0u,
) : Ipv6ExtensionHeader(nextHeader = nextHeader, length = length) {
    companion object {
        const val MIN_LENGTH: UByte = 8u // next header, reserved, fragment offset, and identification

        fun fromStream(
            stream: ByteBuffer,
            nextheader: UByte,
        ): Ipv6Fragment {
            val fragmentOffsetRMByte = stream.getShort()
            val fragmentOffset = ((fragmentOffsetRMByte and 0b111111111111100).toUInt() shr 3).toUShort()
            val moreFlag = (fragmentOffsetRMByte and 0b1).toInt() == 1
            val identification = stream.getInt().toUInt()
            return Ipv6Fragment(nextheader, MIN_LENGTH, fragmentOffset, moreFlag, identification)
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        val buffer = ByteBuffer.allocate(MIN_LENGTH.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.putShort((fragmentOffset.toInt() shl 3 or if (moreFlag) 1 else 0).toShort())
        buffer.putInt(identification.toInt())
        return buffer.array()
    }
}
