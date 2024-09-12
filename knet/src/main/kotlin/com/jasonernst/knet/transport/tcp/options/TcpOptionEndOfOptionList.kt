package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
data class TcpOptionEndOfOptionList(
    override val type: TcpOptionTypeSupported = TcpOptionTypeSupported.EndOfOptionList,
    override val size: UByte = 0x01u,
) : TcpOption(type = TcpOptionTypeSupported.EndOfOptionList, size = 0x01u) {
    override fun toString(): String = "TCPOptionEndOfOptionList(kind=${type.kind} size=$size)"
}
