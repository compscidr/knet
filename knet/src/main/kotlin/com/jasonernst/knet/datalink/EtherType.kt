package com.jasonernst.knet.datalink

import kotlin.collections.first

/**
 * https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
 * https://en.wikipedia.org/wiki/EtherType
 */
enum class EtherType(
    val value: UShort,
) {
    IPv4(0x0800u),
    ARP(0x0806u),
    IPv6(0x86DDu),
    ;

    companion object {
        fun fromValue(value: UShort) = EtherType.entries.first { it.value == value }
    }
}
