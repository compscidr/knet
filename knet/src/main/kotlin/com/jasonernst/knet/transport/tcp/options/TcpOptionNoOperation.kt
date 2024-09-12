package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
object TcpOptionNoOperation : TcpOption(type = TcpOptionTypeSupported.NoOperation, size = 0x01u) {
    override fun toString(): String = "TCPOptionNoOperation(kind=${type.kind} size=$size)"
}
