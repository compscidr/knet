package com.jasonernst.knet.ip

import com.jasonernst.knet.PacketTooShortException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.Inet4Address
import java.net.Inet6Address
import java.nio.ByteBuffer

class IpHeaderTest {
    @Test fun tooShortBuffer() {
        val stream = ByteBuffer.allocate(0)
        assertThrows<PacketTooShortException> {
            IpHeader.fromStream(stream)
        }
    }

    @Test fun nonIPPacket() {
        val stream = ByteBuffer.allocate(1)
        stream.put(0x00)
        stream.rewind()
        assertThrows<IllegalArgumentException> {
            IpHeader.fromStream(stream)
        }
    }

    @Test fun mismatchSourceDest() {
        val source = Inet4Address.getByName("127.0.0.1")
        val destination = Inet6Address.getByName("::1")
        assertThrows<RuntimeException> {
            IpHeader.createIPHeader(source, destination, IpType.TCP, 0)
        }
    }
}
