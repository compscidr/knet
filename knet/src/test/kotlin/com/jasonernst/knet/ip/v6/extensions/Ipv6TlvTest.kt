package com.jasonernst.knet.ip.v6.extensions

import com.jasonernst.knet.PacketTooShortException
import com.jasonernst.knet.ip.v6.extenions.Ipv6DestinationHopByHopType
import com.jasonernst.knet.ip.v6.extenions.Ipv6Tlv
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class Ipv6TlvTest {
    @Test fun optionDataLengthMismatch() {
        assertThrows<IllegalArgumentException> {
            Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 0u, byteArrayOf(0, 2))
        }
    }

    @Test fun equalsTest() {
        val tlv1 = Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 1u, byteArrayOf(0))
        val tlv2 = Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 1u, byteArrayOf(0))
        assertEquals(tlv1, tlv2)
        assertEquals(tlv1.optionType, tlv2.optionType)
        assertEquals(tlv1.optionDataLength, tlv2.optionDataLength)
        assertArrayEquals(tlv1.optionData, tlv2.optionData)

        assertNotEquals(tlv1, null)
        assertNotEquals(tlv1, Any())
        assertEquals(tlv1, tlv1)

        val tlv3 = Ipv6Tlv(Ipv6DestinationHopByHopType.PadN, 1u, byteArrayOf(0))
        assertNotEquals(tlv1, tlv3)

        val tlv4 = Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 2u, byteArrayOf(0, 0))
        assertNotEquals(tlv1, tlv4)

        val tlv5 = Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 1u, byteArrayOf(1))
        assertNotEquals(tlv1, tlv5)
    }

    @Test fun tooShort() {
        assertThrows<PacketTooShortException> {
            Ipv6Tlv.fromStream(ByteBuffer.allocate(0))
        }

        assertThrows<PacketTooShortException> {
            val stream = ByteBuffer.wrap(Ipv6Tlv().toByteArray())
            stream.limit(stream.limit() - 1)
            Ipv6Tlv.fromStream(stream)
        }
    }

    @Test fun hashTest() {
        val tlv1 = Ipv6Tlv(Ipv6DestinationHopByHopType.Pad1, 1u, byteArrayOf(0))
        val hashMap = hashMapOf(tlv1 to 1)
        assertEquals(1, hashMap[tlv1])
    }
}
