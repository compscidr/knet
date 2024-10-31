package com.jasonernst.knet.network.nextheader

import com.jasonernst.icmp.common.IcmpHeader
import java.nio.ByteOrder

data class ICMPNextHeaderWrapper(
    val icmpHeader: IcmpHeader,
    override val protocol: UByte,
    override val typeString: String,
) : NextHeader {
    override fun getHeaderLength(): UShort = icmpHeader.size().toUShort()

    override fun toByteArray(order: ByteOrder): ByteArray = icmpHeader.toByteArray(order)
}
