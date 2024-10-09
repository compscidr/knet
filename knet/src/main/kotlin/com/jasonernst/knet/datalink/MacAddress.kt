package com.jasonernst.knet.datalink

import java.nio.ByteBuffer
import kotlin.collections.contentEquals
import kotlin.collections.contentHashCode
import kotlin.collections.map
import kotlin.collections.toByteArray
import kotlin.text.split

/**
 * Represents an Ethernet or Wi-Fi MAC address.
 */
class MacAddress {
    var bytes: ByteArray

    constructor(bytes: ByteArray) {
        if (bytes.size != 6) {
            throw IllegalArgumentException("MAC address must be 6 bytes")
        }
        this.bytes = bytes
    }

    constructor(address: String) {
        this.bytes = address.split(":").map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Ensure that the MAC address is formatted correctly, ie) each byte is outputted in hex and
     * separated by a colon.
     */
    override fun toString(): String {
        val conversionBuffer = ByteBuffer.wrap(bytes)
        val output = StringBuilder()
        var count = 1
        while (conversionBuffer.hasRemaining()) {
            output.append(String.format("%02X", conversionBuffer.get()))
            if (count < 6) {
                output.append(":")
                count++
            }
        }
        return output.toString()
    }

    companion object {
        fun fromStream(stream: ByteBuffer): MacAddress {
            if (stream.remaining() < 6) {
                throw IllegalArgumentException("Not enough bytes to create a MAC address")
            }
            val bytes = ByteArray(6)
            stream.get(bytes)
            return MacAddress(bytes)
        }

        val DUMMY_MAC_SOURCE = MacAddress("14:c0:3e:55:0b:35")
        val DUMMY_MAC_DEST = MacAddress("74:d0:2b:29:a5:18")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as MacAddress

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}
