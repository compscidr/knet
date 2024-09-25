package com.jasonernst.knet.ip.v6.extenions.type

/**
 * https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
 */
enum class Ipv6RoutingType(
    val kind: UByte,
) {
    SourceRouteDeprecated(0u),
    NimrodDeprecated(1u),
    Type2RoutingHeader(2u),
    RplSourceRoute(3u),
    SegmentRouting(4u),
    CRH16(5u),
    CRH32(6u),
    RFC3692StyleExperiment1(253u),
    RFC3692StyleExperiment2(254u),
    Reserved(255u),
    ;

    companion object {
        fun fromKind(kind: UByte) = entries.first { it.kind == kind }
    }
}
