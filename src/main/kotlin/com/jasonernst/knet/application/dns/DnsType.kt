package com.jasonernst.knet.application.dns

/**
 * https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
 * https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
 */
enum class DnsType(
    val value: UShort,
) {
    A(1u),
    NS(2u),
    MD(3u),
    MF(4u),
    CNAME(5u),
    SOA(6u),
    MB(7u),
    MG(8u),
    MR(9u),
    NULL(10u),
    WKS(11u),
    PTR(12u),
    HINFO(13u),
    MINFO(14u),
    MX(15u),
    TXT(16u),

    // qtypes
    AXFR(252u),
    MAILB(253u),
    MAILA(254u),
    ANY(255u),
    ;

    companion object {
        fun fromValue(value: UShort) = entries.first { it.value == value }
    }
}
