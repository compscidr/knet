package com.jasonernst.knet.ip.v6.extenions.routing

/**
 * When we throw this, we expect that a handling system would generate an ICMPv6 error message as
 * spelled out in the Ipv6Routing usecase where we have a non-zero segment. We also expect this
 * if we get a nimrod packet.
 *
 * If Segments Left is non-zero, the node must discard the packet and
 * send an ICMP Parameter Problem, Code 0, message to the packet's
 * Source Address, pointing to the unrecognized Routing Type.
 */
class FatalRoutingException(
    message: String,
) : Exception(message)
