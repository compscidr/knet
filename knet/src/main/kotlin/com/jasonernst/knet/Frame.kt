package com.jasonernst.knet

import com.jasonernst.knet.datalink.EthernetHeader

/**
 * Encapsulates a frame, which includes an Ethernet header and a Packet.
 */
data class Frame(
    val ethernetHeader: EthernetHeader,
    val packet: Packet,
)
