package com.jasonernst.knet.network.ip.v6.extenions.routing

/**
 * When we throw this, we expect that a handling system would skip the routing header and continue
 * processing the packet. For instance is we have a source route header, but segments left is 0.
 */
class NonFatalRoutingException(
    message: String,
) : Exception(message)
