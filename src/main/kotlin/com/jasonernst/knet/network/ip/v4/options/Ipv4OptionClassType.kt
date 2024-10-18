package com.jasonernst.knet.network.ip.v4.options

/**
 * The option classes are:
 *
 *       0 = control
 *       1 = reserved for future use
 *       2 = debugging and measurement
 *       3 = reserved for future use
 *
 *  Since we only have 2 bits, any other value makes no sense and should
 *  rightfully throw an exception when trying to parse it.
 */
enum class Ipv4OptionClassType(
    val kind: UByte,
) {
    Control(0u),
    Reserved1(1u),
    DebuggingAndMeasurement(2u),
    Reserved2(3u),
    ;

    companion object {
        fun fromKind(kind: UByte) = entries.first { it.kind == kind }
    }
}
