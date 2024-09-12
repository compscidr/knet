package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
object TcpOptionEndOfOptionList : TcpOption(type = TcpOptionTypeSupported.EndOfOptionList, size = 0x01u) {
    override fun toString(): String = "TCPOptionEndOfOptionList(kind=${type.kind} size=$size)"
}
