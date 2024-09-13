package com.jasonernst.knet.ip.options

data class Ipv4OptionNoOperation(
    override val isCopied: Boolean,
    override val optionClass: Ipv4OptionClassType,
    override val type: Ipv4OptionType = Ipv4OptionType.NoOperation,
    override val size: UByte = 1u,
) : Ipv4Option(isCopied, optionClass, type, size)
