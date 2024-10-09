package com.jasonernst.knet.network.ip.v4.options

/**
 * From RFC 791:
 *
 * This option may be used between options, for example, to align
 * the beginning of a subsequent option on a 32 bit boundary.
 *
 * May be copied, introduced, or deleted on fragmentation, or for
 * any other reason.
 */
data class Ipv4OptionNoOperation(
    override val isCopied: Boolean = false,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.NoOperation,
    override val size: UByte = 1u,
) : Ipv4Option(isCopied, optionClass, type, size)
