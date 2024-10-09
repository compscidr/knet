package com.jasonernst.knet.network.nextheader

import com.jasonernst.knet.network.ip.IpType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class NextHeaderTests {
    @Test fun unsupportedNextHeaer() {
        assertThrows<IllegalArgumentException> {
            NextHeader.Companion.fromStream(ByteBuffer.allocate(0), IpType.IPV6_FRAG.value)
        }
    }
}
