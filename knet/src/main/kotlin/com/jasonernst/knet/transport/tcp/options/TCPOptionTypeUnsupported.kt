package com.jasonernst.knet.transport.tcp.options

class TCPOptionTypeUnsupported(override val kind: UByte) : TCPOptionType {
    companion object {
        fun fromKind(kind: UByte) = TCPOptionTypeUnsupported(kind)
    }
}
