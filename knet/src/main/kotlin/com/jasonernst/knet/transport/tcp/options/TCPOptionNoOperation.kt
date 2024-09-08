package com.jasonernst.knet.transport.tcp.options

/**
 * Can't use a data class when there are no parameters so using a singleton object instead.
 * Otherwise we'll need to implement equals and hashCode.
 */
object TCPOptionNoOperation : TCPOption(type = TCPOptionTypeSupported.NoOperation, size = 0x01u) {
    override fun toString(): String {
        return "TCPOptionNoOperation(kind=${type.kind} size=$size)"
    }
}
