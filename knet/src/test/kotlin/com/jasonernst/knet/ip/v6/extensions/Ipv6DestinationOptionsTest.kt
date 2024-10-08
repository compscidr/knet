package com.jasonernst.knet.ip.v6.extensions

import com.jasonernst.knet.ip.IpType
import com.jasonernst.knet.ip.v6.extenions.Ipv6DestinationOptions
import com.jasonernst.knet.ip.v6.extenions.Ipv6Tlv
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer

class Ipv6DestinationOptionsTest {
    @Test
    fun lengthOptionsMismatch() {
        assertThrows<IllegalArgumentException> {
            Ipv6DestinationOptions(
                optionData =
                    listOf(
                        Ipv6Tlv(),
                        Ipv6Tlv(),
                    ),
            )
        }

        assertThrows<IllegalArgumentException> {
            Ipv6DestinationOptions(
                length = 3u,
                optionData =
                    listOf(
                        Ipv6Tlv(),
                    ),
            )
        }
    }

    @Test fun toFromStream() {
        val destinationOptions = Ipv6DestinationOptions()
        val stream = ByteBuffer.wrap(destinationOptions.toByteArray())
        val nextHeader = stream.get().toUByte()
        val length = stream.get().toUByte()
        val parsedDestinationOptions = Ipv6DestinationOptions.fromStream(stream, nextHeader, length)
        assertEquals(destinationOptions, parsedDestinationOptions)

        val options = listOf(Ipv6Tlv())
        val optionsSize = (options.sumOf { options.size })
        val destinationOptionsWithOptions =
            Ipv6DestinationOptions(nextHeader = IpType.UDP.value, length = optionsSize.toUInt().toUByte(), optionData = options)
        val stream2 = ByteBuffer.wrap(destinationOptionsWithOptions.toByteArray())
        val nextHeader2 = stream2.get().toUByte()
        assertEquals(IpType.UDP.value, nextHeader2)
        val length2 = stream2.get().toUByte()
        val parsedDestinationOptionsWithOptions = Ipv6DestinationOptions.fromStream(stream2, nextHeader2, length2)
        assertEquals(destinationOptionsWithOptions, parsedDestinationOptionsWithOptions)
    }
}
