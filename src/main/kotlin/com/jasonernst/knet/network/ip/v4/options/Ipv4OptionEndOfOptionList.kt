package com.jasonernst.knet.network.ip.v4.options

/**
 *
 * From RFC 791:
 *
 * This option indicates the end of the option list.  This might
 * not coincide with the end of the internet header according to
 * the internet header length.  This is used at the end of all
 * options, not the end of each option, and need only be used if
 * the end of the options would not otherwise coincide with the end
 * of the internet header.
 *
 * May be copied, introduced, or deleted on fragmentation, or for
 * any other reason.
 */
data class Ipv4OptionEndOfOptionList(
    override val isCopied: Boolean = false,
    override val optionClass: Ipv4OptionClassType = Ipv4OptionClassType.Control,
    override val type: Ipv4OptionType = Ipv4OptionType.EndOfOptionList,
    override val size: UByte = 1u,
) : Ipv4Option(isCopied, optionClass, type, size)
