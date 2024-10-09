package com.jasonernst.knet.transport

import com.jasonernst.knet.network.nextheader.NextHeader
import java.net.InetAddress

/**
 * Common functionality across Transport (TCP, UDP) headers
 */
interface TransportHeader : NextHeader {
    var sourcePort: UShort
    var destinationPort: UShort
    var checksum: UShort

    // swap the source and destination ports
    fun swapSourceAndDestination() {
        val temp = sourcePort
        sourcePort = destinationPort
        destinationPort = temp
    }

    /**
     * Verify that the checksum is correct
     */
    fun verifyChecksum(
        sourceAddress: InetAddress,
        destinationAddress: InetAddress,
    ): Boolean {
        TODO()
    }
}
