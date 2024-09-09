package com.jasonernst.knet.nextheader

import com.jasonernst.icmp_common.ICMPHeader
import java.nio.ByteOrder

class ICMPNextHeaderWrapper(
    private val icmpHeader: ICMPHeader,
    override val protocol: UByte,
    override val typeString: String,
) : NextHeader {
    override fun getHeaderLength(): UShort = icmpHeader.size().toUShort()

    override fun toByteArray(order: ByteOrder): ByteArray = icmpHeader.toByteArray(order)
}
