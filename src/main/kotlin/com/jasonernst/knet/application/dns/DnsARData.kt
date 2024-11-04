package com.jasonernst.knet.application.dns

import java.net.Inet4Address
import java.nio.ByteBuffer

class DnsARData(
    val address: Inet4Address,
) : DnsRData(data = address.address) {
    companion object {
        fun fromStream(stream: ByteBuffer): DnsARData {
            val inet4Address = Inet4Address.getByAddress(ByteArray(4) { stream.get() }) as Inet4Address
            return DnsARData(inet4Address)
        }
    }

    override fun toString(): String = "DnsARData(address=$address)"
}
