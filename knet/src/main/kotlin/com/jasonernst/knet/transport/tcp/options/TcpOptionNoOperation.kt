package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
data class TcpOptionNoOperation(
    override val type: TcpOptionTypeSupported = TcpOptionTypeSupported.NoOperation,
    override val size: UByte = 0x01u,
) : TcpOption(type = type, size = size) {
    override fun toString(): String = "TCPOptionNoOperation(kind=${type.kind} size=$size)"
}
