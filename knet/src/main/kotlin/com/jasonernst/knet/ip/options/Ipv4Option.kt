package com.jasonernst.knet.ip.options

import com.jasonernst.knet.PacketTooShortException
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

// because kotlin doesn't have a direct conversion function apparently...
// https://stackoverflow.com/questions/46401879/boolean-int-conversion-in-kotlin
fun Boolean.toInt() = if (this) 1 else 0

/**
 * From RFC791, page 15:
 *
 * The option field is variable in length.  There may be zero or more
 *     options.  There are two cases for the format of an option:
 *
 *       Case 1:  A single octet of option-type.
 *
 *       Case 2:  An option-type octet, an option-length octet, and the
 *                actual option-data octets.
 *
 *     The option-length octet counts the option-type octet and the
 *     option-length octet as well as the option-data octets.
 *
 *     The option-type octet is viewed as having 3 fields:
 *
 *       1 bit   copied flag,
 *       2 bits  option class,
 *       5 bits  option number.
 *
 *     The copied flag indicates that this option is copied into all
 *     fragments on fragmentation.
 *
 *       0 = not copied
 *       1 = copied
 */
abstract class Ipv4Option(
    open val isCopied: Boolean = true,
    open val optionClass: Ipv4OptionClassType,
    open val type: Ipv4OptionType,
    open val size: UByte,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(Ipv4Option::class.java)

        fun parseOptions(
            stream: ByteBuffer,
            limit: Int = stream.limit(),
        ): List<Ipv4Option> {
            val options = ArrayList<Ipv4Option>()
            while (stream.position() + 1 <= limit) {
                val kindOctet = stream.get().toUByte()
                // high bit is copied flag
                val isCopied = kindOctet.toInt() and 0b10000000 == 0b10000000
                val classByte = (kindOctet.toInt() and 0b01100000) shr 5
                val optionClass = Ipv4OptionClassType.fromKind(classByte.toUByte())
                val kind = (kindOctet.toInt() and 0b00011111).toUByte()
                if (kind == Ipv4OptionType.EndOfOptionList.kind) {
                    options.add(Ipv4OptionEndOfOptionList(isCopied, optionClass))
                    break
                } else if (kind == Ipv4OptionType.NoOperation.kind) {
                    options.add(Ipv4OptionNoOperation(isCopied, optionClass))
                } else if (kind == Ipv4OptionType.Security.kind) {
                    options.add(Ipv4OptionSecurity.fromStream(stream))
                } else {
                    if (stream.remaining() < 1) {
                        throw PacketTooShortException("Can't determine length of ipv4 option because we have no bytes left")
                    }
                    // this length includes the previous two bytes which is why we need adjustment
                    // we don't apply it directly to length because we want to construct the option
                    // with the correct length which includes the first two fields
                    val length = (stream.get().toUByte())
                    if (stream.remaining() < length.toInt() - 2) {
                        throw PacketTooShortException("Can't parse ipv4 option because we don't have enough bytes left for the data")
                    }
                    val data = ByteArray(length.toInt() - 2)
                    stream.get(data)

                    val type =
                        try {
                            Ipv4OptionType.fromKind(kind)
                        } catch (e: NoSuchElementException) {
                            Ipv4OptionType.Unknown
                        }
                    options.add(Ipv4OptionUnknown(isCopied, optionClass, type, length, data))
                }
            }
            return options
        }
    }

    open fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val copiedInt = (isCopied.toInt() shl 7)
        val classInt = optionClass.kind.toInt() shl 5
        val typeInt = type.kind.toInt()
        val typeByte = (copiedInt + classInt + typeInt).toByte()
        return byteArrayOf(typeByte)
    }
}
