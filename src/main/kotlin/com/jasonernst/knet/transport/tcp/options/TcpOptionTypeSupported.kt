package com.jasonernst.knet.transport.tcp.options

/**
 * https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
 */
enum class TcpOptionTypeSupported(
    override val kind: UByte,
) : TcpOptionType {
    EndOfOptionList(0u),
    NoOperation(1u),
    MaximumSegmentSize(2u),
    WindowScale(3u),
    SACKPermitted(4u),
    SACK(5u),
    Echo(6u),
    EchoReply(7u),
    Timestamps(8u),
    PartialOrderConnectionPermitted(8u),
    PartialOrderServiceProfile(10u),
    CC(11u),
    CCNew(12u),
    CCEcho(13u),
    AlternateChecksumRequest(14u),
    AlternateChecksumData(15u),
    Skeeter(16u),
    Bubba(17u),
    TrailerChecksumOption(18u),
    MD5SignatureOption(19u),
    SCPS(20u),
    SelectiveNegativeAcknowledgements(21u),
    RecordBoundaries(22u),
    CorruptionExperienced(23u),
    SNAP(24u),
    Unassigned(25u),
    TCPCompressionFilter(26u),
    QuickStartResponse(27u),
    UserTimeout(28u),
    TCPAuthenticationOption(29u),
    MultipathCapable(30u),
    TCPFastOpen(34u),

    // fake type we defined for when we don't have the type in the enum
    Unsupported(99u),
    ;

    companion object {
        fun fromKind(kind: UByte) = entries.first { it.kind == kind }
    }
}
