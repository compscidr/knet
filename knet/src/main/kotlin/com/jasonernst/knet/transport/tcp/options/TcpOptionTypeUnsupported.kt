package com.jasonernst.knet.transport.tcp.options

class TcpOptionTypeUnsupported(
    override val kind: UByte,
) : TcpOptionType {
    companion object {
        fun fromKind(kind: UByte) = TcpOptionTypeUnsupported(kind)
    }
}
