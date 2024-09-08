package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
object TCPOptionEndOfOptionList : TCPOption(type = TCPOptionTypeSupported.EndOfOptionList, size = 0x01u) {
    override fun toString(): String {
        return "TCPOptionEndOfOptionList(kind=${type.kind} size=$size)"
    }
}
