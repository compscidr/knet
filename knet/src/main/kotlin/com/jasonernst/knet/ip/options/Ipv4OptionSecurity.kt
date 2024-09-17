package com.jasonernst.knet.ip.options

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * From RFC 791:
 * - must be copied
 * - appears at most once in a datagram
 *
 * Security:
 * Specifies one of 16 levels of security (eight of which are
 * reserved for future use).
 *
 * Compartments:
 * An all zero value is used when the information transmitted is
 * not compartmented.  Other values for the compartments field
 * may be obtained from the Defense Intelligence Agency.
 *
 * Handling Restrictions:
 * The values for the control and release markings are
 * alphanumeric digraphs and are defined in the Defense
 * Intelligence Agency Manual DIAM 65-19, "Standard Security
 * Markings".
 *
 * Provides a means to segregate traffic and define controlled
 * communities of interest among subscribers. The TCC values are
 * trigraphs, and are available from HQ DCA Code 530.
 */
data class Ipv4OptionSecurity(
    override val isCopied: Boolean = true,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.Security,
    override val size: UByte = OPTION_SIZE,
    val security: Ipv4OptionSecurityType = Ipv4OptionSecurityType.Unclassified,
    val compartment: UShort = 0u,
    val handlingRestrictions: UShort = 0u,
    val tcc: UInt = 0u, // even though we 32 bits, this field is actually 24...whyyyyy.
) : Ipv4Option(isCopied, optionClass, type, size) {
    companion object {
        private val logger = LoggerFactory.getLogger(javaClass)
        val OPTION_SIZE: UByte = 11u

        fun fromStream(
            stream: ByteBuffer,
            isCopied: Boolean,
            optionClass: Ipv4OptionClassType,
            size: UByte,
        ): Ipv4OptionSecurity {
            if (stream.remaining() < OPTION_SIZE.toInt() - 2) {
                throw PacketTooShortException(
                    "Stream must have at least ${OPTION_SIZE - 2u} " +
                        "remaining bytes remaining to parse Ipv4OptionSecurity, we only have " +
                        "${stream.remaining()} bytes",
                )
            }
            val security = Ipv4OptionSecurityType.fromKind(stream.getShort().toUShort())
            val compartment = stream.getShort().toUShort()
            val handlingRestrictions = stream.getShort().toUShort()
            val tccHighByte = stream.get().toUInt() shl 16
            val tccLowWord = stream.getShort().toUInt()
            val tcc = tccHighByte.toInt() or tccLowWord.toInt()
            logger.debug("Stream position: ${stream.position()} remaining: ${stream.remaining()}")
            return Ipv4OptionSecurity(
                isCopied = isCopied,
                optionClass = optionClass,
                size = size,
                security = security,
                compartment = compartment,
                handlingRestrictions = handlingRestrictions,
                tcc = tcc.toUInt(),
            )
        }
    }

    override fun toByteArray(order: ByteOrder): ByteArray {
        logger.debug("SIZE: $size")
        val buffer = ByteBuffer.allocate(size.toInt())
        buffer.order(order)
        buffer.put(super.toByteArray(order))
        buffer.putShort(security.kind.toShort())
        buffer.putShort(compartment.toShort())
        buffer.putShort(handlingRestrictions.toShort())
        buffer.put((tcc shr 16).toByte())
        buffer.putShort((tcc and 0xFFFFu).toShort())
        return buffer.array()
    }
}
