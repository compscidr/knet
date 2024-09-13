package com.jasonernst.knet.ip.options

data class Ipv4OptionEndOfOptionList(
    override val isCopied: Boolean,
    override val optionClass: Ipv4OptionClassType,
    override val type: Ipv4OptionType = Ipv4OptionType.EndOfOptionList,
    override val size: UByte = 1u,
) : Ipv4Option(isCopied, optionClass, type, size)
