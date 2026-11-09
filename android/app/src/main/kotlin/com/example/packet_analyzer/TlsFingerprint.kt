package com.example.packet_analyzer

import java.security.MessageDigest

/**
 * JA3 and JA4 client fingerprints, read from the cleartext ClientHello. They identify the TLS library
 * that opened a connection, which stays visible when everything after the handshake is encrypted.
 * Only a whole ClientHello yields a fingerprint: a truncated one would hash to a different value.
 */
object TlsFingerprint {
    data class Fingerprints(val ja3: String, val ja4: String)

    private const val RECORD_HANDSHAKE = 22
    private const val HANDSHAKE_CLIENT_HELLO = 1
    private const val HEADERS = 9 // 5-byte record header, 4-byte handshake header
    private const val EXT_SNI = 0x0000
    private const val EXT_GROUPS = 0x000a
    private const val EXT_POINT_FORMATS = 0x000b
    private const val EXT_SIG_ALGS = 0x000d
    private const val EXT_ALPN = 0x0010
    private const val EXT_VERSIONS = 0x002b
    private const val EMPTY_HASH = "000000000000"

    // GREASE values (RFC 8701) are random by design and would make every fingerprint unique
    private fun isGrease(v: Int) = (v and 0x0F0F) == 0x0A0A && (v ushr 8) == (v and 0xFF)

    private fun u8(p: ByteArray, i: Int) = p[i].toInt() and 0xFF
    private fun u16(p: ByteArray, i: Int) = (u8(p, i) shl 8) or u8(p, i + 1)

    /** Null unless [payload] starts with a complete ClientHello. */
    fun fromClientHello(payload: ByteArray): Fingerprints? {
        val p = payload
        if (p.size < HEADERS + 2 + 32 + 1 || u8(p, 0) != RECORD_HANDSHAKE || u8(p, 5) != HANDSHAKE_CLIENT_HELLO) return null
        val helloLength = (u8(p, 6) shl 16) or u16(p, 7)
        val end = HEADERS + helloLength
        if (end > p.size) return null

        var i = HEADERS
        val legacyVersion = u16(p, i)
        i += 2 + 32
        i += 1 + u8(p, i)
        if (i + 2 > end) return null

        val cipherBytes = u16(p, i)
        i += 2
        if (i + cipherBytes > end) return null
        val ciphers = (0 until cipherBytes / 2).map { u16(p, i + it * 2) }.filterNot(::isGrease)
        i += cipherBytes
        if (i + 1 > end) return null
        i += 1 + u8(p, i)

        val extensions = mutableListOf<Int>()
        var groups = emptyList<Int>()
        var pointFormats = emptyList<Int>()
        var sigAlgs = emptyList<Int>()
        var versions = emptyList<Int>()
        var alpn: ByteArray? = null
        var hasSni = false

        if (i + 2 <= end) {
            val extEnd = minOf(i + 2 + u16(p, i), end)
            i += 2
            while (i + 4 <= extEnd) {
                val type = u16(p, i)
                val length = u16(p, i + 2)
                val data = i + 4
                if (data + length > extEnd) return null
                if (!isGrease(type)) {
                    extensions.add(type)
                    when (type) {
                        EXT_SNI -> hasSni = true
                        EXT_GROUPS -> groups = u16List(p, data + 2, u16Safe(p, data, length))
                        EXT_POINT_FORMATS -> pointFormats =
                            if (length >= 1) (0 until minOf(u8(p, data), length - 1)).map { u8(p, data + 1 + it) } else emptyList()
                        EXT_SIG_ALGS -> sigAlgs = u16List(p, data + 2, u16Safe(p, data, length))
                        EXT_VERSIONS -> versions =
                            if (length >= 1) u16List(p, data + 1, minOf(u8(p, data), length - 1)) else emptyList()
                        EXT_ALPN -> alpn = firstAlpn(p, data, length)
                    }
                }
                i = data + length
            }
        }

        return Fingerprints(
            ja3 = ja3(legacyVersion, ciphers, extensions, groups, pointFormats),
            ja4 = ja4(legacyVersion, versions, hasSni, ciphers, extensions, sigAlgs, alpn)
        )
    }

    private fun u16Safe(p: ByteArray, data: Int, length: Int) = if (length >= 2) minOf(u16(p, data), length - 2) else 0

    private fun u16List(p: ByteArray, start: Int, bytes: Int) =
        (0 until bytes / 2).map { u16(p, start + it * 2) }.filterNot(::isGrease)

    private fun firstAlpn(p: ByteArray, data: Int, length: Int): ByteArray? {
        if (length < 3) return null
        val first = u8(p, data + 2)
        if (first == 0 || data + 3 + first > data + length) return null
        return p.copyOfRange(data + 3, data + 3 + first)
    }

    private fun ja3(version: Int, ciphers: List<Int>, extensions: List<Int>, groups: List<Int>, formats: List<Int>): String {
        val text = "$version,${ciphers.joinToString("-")},${extensions.joinToString("-")}," +
            "${groups.joinToString("-")},${formats.joinToString("-")}"
        return hex(MessageDigest.getInstance("MD5").digest(text.toByteArray()))
    }

    private fun ja4(
        legacyVersion: Int, versions: List<Int>, hasSni: Boolean,
        ciphers: List<Int>, extensions: List<Int>, sigAlgs: List<Int>, alpn: ByteArray?
    ): String {
        val version = when (versions.maxOrNull() ?: legacyVersion) {
            0x0304 -> "13"
            0x0303 -> "12"
            0x0302 -> "11"
            0x0301 -> "10"
            0x0300 -> "s3"
            0x0200 -> "s2"
            0x0100 -> "s1"
            else -> "00"
        }
        val prefix = "t$version${if (hasSni) "d" else "i"}" +
            "%02d%02d".format(minOf(ciphers.size, 99), minOf(extensions.size, 99)) + alpnCode(alpn)

        val cipherHash = truncatedSha256(ciphers.map(::hex4).sorted().joinToString(","), ciphers.isEmpty())
        val sortedExtensions = extensions.filter { it != EXT_SNI && it != EXT_ALPN }.map(::hex4).sorted().joinToString(",")
        val extensionText = if (sigAlgs.isEmpty()) sortedExtensions else "${sortedExtensions}_${sigAlgs.joinToString(",", transform = ::hex4)}"
        val extensionHash = truncatedSha256(extensionText, sortedExtensions.isEmpty())
        return "${prefix}_${cipherHash}_$extensionHash"
    }

    private fun alpnCode(alpn: ByteArray?): String {
        if (alpn == null || alpn.isEmpty()) return "00"
        val first = alpn.first().toInt().toChar()
        val last = alpn.last().toInt().toChar()
        if (first.isLetterOrDigit() && first.code < 128 && last.isLetterOrDigit() && last.code < 128) return "$first$last"
        val text = hex(alpn)
        return "${text.first()}${text.last()}"
    }

    private fun truncatedSha256(text: String, empty: Boolean): String =
        if (empty) EMPTY_HASH else hex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray())).substring(0, 12)

    private fun hex4(v: Int) = "%04x".format(v)

    private fun hex(bytes: ByteArray) = buildString(bytes.size * 2) {
        for (b in bytes) append("%02x".format(b))
    }
}
