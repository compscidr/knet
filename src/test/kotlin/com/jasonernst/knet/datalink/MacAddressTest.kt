package com.jasonernst.knet.datalink

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class MacAddressTest {
    @Test fun tooShort() {
        assertThrows<IllegalArgumentException> {
            MacAddress(ByteArray(0))
        }

        assertThrows<IllegalArgumentException> {
            MacAddress.fromStream(ByteBuffer.allocate(0))
        }
    }

    @Test fun equalsTest() {
        val macAddress = MacAddress(ByteArray(6) { 0x00 })
        val macAddress2 = MacAddress(ByteArray(6) { 0x00 })
        assertEquals(macAddress, macAddress2)
        assertEquals(macAddress, macAddress)
        assertNotEquals(macAddress, null)
        val macAddress3 = MacAddress(ByteArray(6) { 0x01 })
        assertNotEquals(macAddress, macAddress3)
        assertNotEquals(macAddress, Any())

        assertEquals(macAddress.hashCode(), macAddress2.hashCode())
    }
}
