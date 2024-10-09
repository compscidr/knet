package com.jasonernst.knet.network.ip.v4.options

enum class Ipv4OptionSecurityType(
    val kind: UShort,
) {
    Unclassified(0u),
    Confidential(0b1111000100110101u),
    EFTO(0b0111100010011010u),
    MMMM(0b1011110001001101u),
    PROG(0b0101111000100110u),
    Restricted(0b1010111100010011u),
    Secret(0b1101011110001000u),
    TopSecret(0b0110101111000101u),
    Reserved(0b0011010111100010u),
    Reserved2(0b1001101011110001u),
    Reserved3(0b0100110101111000u),
    Reserved4(0b0010010010111101u),
    Reserved5(0b0001001101011110u),
    Reserved6(0b1000100110101111u),
    Reserved7(0b1100010011010110u),
    Reserved8(0b1110001001101011u),
    ;

    companion object {
        fun fromKind(kind: UShort): Ipv4OptionSecurityType =
            entries.find { it.kind == kind }
                ?: throw IllegalArgumentException("Unknown Ipv4OptionSecurityType kind: $kind")
    }
}
