package com.jasonernst.knet.network.nextheader

import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class NextHeaderTests {
    @Test fun unsupportedNextHeader() {
        assertThrows<IllegalArgumentException> {
            val ipV6Header = Ipv6Header(protocol = IpType.IPV6_FRAG.value)
            NextHeader.Companion.fromStream(ipV6Header, ByteBuffer.allocate(0))
        }
    }
}
