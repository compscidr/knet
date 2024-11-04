package com.jasonernst.knet.application.dns

/**
 * https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
 */
enum class DnsQClass(
    val value: UShort,
) {
    IN(1u),
    CS(2u),
    CH(3u),
    HS(4u),
    ;

    companion object {
        fun fromValue(value: UShort) = entries.first { it.value == value }
    }
}
