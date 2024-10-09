package com.jasonernst.knet.ip.v4.options

/**
 * https://datatracker.ietf.org/doc/html/rfc791 page 15
 */
enum class Ipv4OptionType(
    val kind: UByte,
) {
    EndOfOptionList(0u),
    NoOperation(1u),
    Security(2u),
    LooseSourceRouting(3u),
    StrictSourceRouting(9u),
    RecordRoute(7u),
    StreamId(8u),
    TimeStamp(4u),

    // fake type we defined for when we don't have the type in the enum
    Unknown(31u), // max value since this is 5 bits
    ;

    companion object {
        fun fromKind(kind: UByte) = entries.first { it.kind == kind }
    }
}
