package com.jasonernst.knet.ip

import java.nio.ByteOrder

/**
 * Defines a type-length-value (TLV) extension header for IPv6 packets. Note that not all of the
 * well-defined Ipv6 extension headers support this.
 *
 * https://www.rfc-editor.org/rfc/rfc6564#page-4
 * https://www.rfc-editor.org/rfc/rfc7045.html
 */
abstract class IPv6ExtensionHeader(val nextHeader: UByte, val length: UByte, val data: ByteArray) {
    abstract fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray
}