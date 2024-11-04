package com.jasonernst.knet.application.dns

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Domain Name Service Message implementation:
 * https://datatracker.ietf.org/doc/html/rfc1035
 */
data class DnsMessage(
    val header: DnsHeader,
    val questions: List<DnsQuestion> = ArrayList(),
    val answers: List<DnsRecord> = ArrayList(),
    val authorities: List<DnsRecord> = ArrayList(),
    val additional: List<DnsRecord> = ArrayList(),
) {
    companion object {
        val MAX_UDP_SIZE = 512 // https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4

        fun fromStream(stream: ByteBuffer): DnsMessage {
            // first parse the header to determine how many question / answer records there are
            val start = stream.position().toUShort()
            val header = DnsHeader.fromStream(stream)

            // parse the questions
            val questions = mutableListOf<DnsQuestion>()
            for (i in 0 until header.qdCount.toInt()) {
                questions.add(DnsQuestion.fromStream(stream, start))
            }

            // parse the answers
            val answers = mutableListOf<DnsRecord>()
            for (i in 0 until header.anCount.toInt()) {
                answers.add(DnsRecord.fromStream(stream, start))
            }

            // parse the authority records
            val authorities = mutableListOf<DnsRecord>()
            for (i in 0 until header.nsCount.toInt()) {
                authorities.add(DnsRecord.fromStream(stream, start))
            }

            // parse the additional records
            val additionals = mutableListOf<DnsRecord>()
            for (i in 0 until header.arCount.toInt()) {
                additionals.add(DnsRecord.fromStream(stream, start))
            }

            return DnsMessage(header, questions, answers, authorities, additionals)
        }
    }

    fun size(): Int {
        var size = header.size()
        for (question in questions) {
            size += question.size()
        }
        for (answer in answers) {
            size += answer.size()
        }
        for (authority in authorities) {
            size += authority.size()
        }
        for (addition in additional) {
            size += addition.size()
        }
        return size
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        val buffer = ByteBuffer.allocate(size())
        buffer.order(order)
        buffer.put(header.toByteArray(order))
        for (question in questions) {
            buffer.put(question.toByteArray(order))
        }
        for (answer in answers) {
            buffer.put(answer.toByteArray(order))
        }
        for (authority in authorities) {
            buffer.put(authority.toByteArray(order))
        }
        for (addition in additional) {
            buffer.put(addition.toByteArray(order))
        }
        return buffer.array()
    }
}
