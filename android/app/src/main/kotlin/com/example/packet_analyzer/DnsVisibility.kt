package com.example.packet_analyzer

/**
 * Android moves its resolver onto DNS over TLS or HTTPS whenever the DNS server supports it, and every
 * name then disappears from view: on a stock phone not one plain DNS packet crossed the tunnel. Refusing
 * those connections inside the tunnel makes the resolver fall back to plain DNS, which detection can
 * read. The price, while capture runs, is that DNS leaves the phone unencrypted.
 */
object DnsVisibility {
    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17
    private const val PORT_HTTPS = 443
    private const val PORT_DOT = 853

    // The resolvers given to VpnService.Builder
    private val RESOLVERS_V4 = setOf(0x08080808, 0x08080404)
    private const val RESOLVER_V6_PREFIX_HIGH = 0x2001486048600000L
    private val RESOLVER_V6_SUFFIXES = setOf(0x8888L, 0x8844L)

    private fun u8(p: ByteArray, i: Int) = p[i].toInt() and 0xFF

    private fun long(p: ByteArray, start: Int): Long {
        var v = 0L
        for (i in start until start + 8) v = (v shl 8) or u8(p, i).toLong()
        return v
    }

    /** True for a packet carrying encrypted DNS, which the relay should not forward. */
    fun isEncryptedDns(packet: ByteArray): Boolean {
        if (packet.isEmpty()) return false
        when (u8(packet, 0) ushr 4) {
            4 -> {
                val headerLength = (u8(packet, 0) and 0x0F) * 4
                if (packet.size < headerLength + 4) return false
                val protocol = u8(packet, 9)
                val port = (u8(packet, headerLength + 2) shl 8) or u8(packet, headerLength + 3)
                val destination = (u8(packet, 16) shl 24) or (u8(packet, 17) shl 16) or (u8(packet, 18) shl 8) or u8(packet, 19)
                return matches(protocol, port, destination in RESOLVERS_V4)
            }
            6 -> {
                if (packet.size < 44) return false
                val protocol = u8(packet, 6)
                val port = (u8(packet, 42) shl 8) or u8(packet, 43)
                val toResolver = long(packet, 24) == RESOLVER_V6_PREFIX_HIGH && long(packet, 32) in RESOLVER_V6_SUFFIXES
                return matches(protocol, port, toResolver)
            }
            else -> return false
        }
    }

    private fun matches(protocol: Int, port: Int, toResolver: Boolean): Boolean {
        if (protocol == PROTO_TCP && port == PORT_DOT) return true
        return toResolver && port == PORT_HTTPS && (protocol == PROTO_TCP || protocol == PROTO_UDP)
    }
}
