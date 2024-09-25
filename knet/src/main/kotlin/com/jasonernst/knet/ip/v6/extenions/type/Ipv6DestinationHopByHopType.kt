package com.jasonernst.knet.ip.v6.extenions.type

/**
 * https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
 */
enum class Ipv6DestinationHopByHopType(
    val kind: UByte,
) {
    Pad1(0u),
    PadN(1u),
    JumboPayload(0xC2u),
    RPLOption(0x23u),
    RPLOptionDeprecated(0x63u),
    TunnelEncapsulationLimit(0x04u),
    RouterAlert(0x05u),
    QuickStart(0x26u),
    Calipso(0x07u),
    SMF_DPD(0x08u),
    HomeAddress(0xC9u),
    EndpointIdentificationDeprecated(0x8Au),
    ILNPNonce(0x8Bu),
    LineIdentificationOption(0x8Cu),
    Deprecated(0x4Du),
    MPLOption(0x6Du),
    IP_DFF(0xEEu),
    PDM(0x0Fu),
    MinimumPathMTUHopByHopOption(0x30u),
    IOAMDestinationOptionAndIOAMHopByHopOption(0x11u),
    IOAMDestinationOptionAndIOAMHopByHopOption2(0x31u),
    AltMark(0x12u),
    RFC3692StyleExperiment1(0x1Eu),
    RFC3692StyleExperiment2(0x3Eu),
    RFC3692StyleExperiment3(0x5Eu),
    RFC3692StyleExperiment4(0x7Eu),
    RFC3692StyleExperiment5(0x9Eu),
    RFC3692StyleExperiment6(0xBEu),
    RFC3692StyleExperiment7(0xDEu),
    RFC3692StyleExperiment8(0xFEu),
    ;

    companion object {
        fun fromKind(kind: UByte) = entries.first { it.kind == kind }
    }
}
