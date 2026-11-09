package com.example.packet_analyzer

/**
 * The canonical packet record: the one shape every capture back-end hands to the analysis
 * pipeline. VPN mode builds it from a TUN read, root mode from an AF_PACKET read. Nothing
 * above this file may branch on which back-end produced a record, except to report
 * [FIELD_CAPTURE_MODE] as provenance.
 */
object PacketRecord {
    const val MODE_VPN = "vpn"
    const val MODE_ROOT = "root"
    const val FIELD_CAPTURE_MODE = "captureMode"

    /** Resolves the app that owns a flow; arguments are transport, outgoing, srcIp, srcPort, dstIp, dstPort. */
    fun interface OwningAppResolver {
        fun resolve(transport: Int, isOutgoing: Boolean, sourceIp: String, sourcePort: Int, destIp: String, destPort: Int): String?
    }

    fun fromIpPacket(
        packet: ByteArray,
        isOutgoing: Boolean,
        captureMode: String,
        resolver: OwningAppResolver? = null
    ): Map<String, Any>? {
        if (packet.isEmpty()) return null
        return when ((packet[0].toInt() shr 4) and 0x0F) {
            4 -> parseIpv4Packet(packet, isOutgoing, captureMode, resolver)
            6 -> parseIpv6Packet(packet, isOutgoing, captureMode, resolver)
            else -> null
        }
    }

    /** ARP only exists below the IP layer, so only root mode can ever produce this record. */
    fun fromArp(senderMac: String, senderIp: String, targetIp: String, size: Int, isOutgoing: Boolean, captureMode: String): Map<String, Any> =
        mapOf(
            "protocol" to "ARP",
            "sourceIp" to senderIp,
            "destinationIp" to targetIp,
            "sourcePort" to 0,
            "destinationPort" to 0,
            "size" to size,
            "timestamp" to System.currentTimeMillis(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to "ARP",
            "flags" to "",
            "owningApp" to "",
            "senderIp" to senderIp,
            "senderMac" to senderMac,
            FIELD_CAPTURE_MODE to captureMode
        )

    private fun parseIpv4Packet(
        packet: ByteArray,
        isOutgoing: Boolean,
        captureMode: String,
        resolver: OwningAppResolver?
    ): Map<String, Any>? {
        if (packet.size < 20) return null

        val protocol = packet[9].toInt() and 0xFF
        val sourceIP = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}." +
                "${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
        val destIP = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}." +
                "${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

        val ihl = (packet[0].toInt() and 0x0F) * 4
        // Validate IHL - must be at least 20 and within packet bounds
        if (ihl < 20 || ihl > packet.size) {
            return null
        }
        val protocolName: String
        var sourcePort = 0
        var destPort = 0
        var tcpFlags = ""

        if (ihl + 4 <= packet.size) {
            when (protocol) {
                6 -> {
                    protocolName = "TCP"
                    sourcePort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                    tcpFlags = extractTcpFlags(packet, ihl)
                }
                17 -> {
                    protocolName = "UDP"
                    sourcePort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                }
                1 -> protocolName = "ICMP"
                else -> protocolName = "Other($protocol)"
            }
        } else {
            protocolName = when (protocol) {
                6 -> "TCP"
                17 -> "UDP"
                1 -> "ICMP"
                else -> "Other($protocol)"
            }
        }

        // Determine application name based on port
        val appName = getApplicationName(protocolName, if (isOutgoing) destPort else sourcePort)
        val owningApp = if (protocol == 6 || protocol == 17) {
            resolver?.resolve(protocol, isOutgoing, sourceIP, sourcePort, destIP, destPort)
        } else null

        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to System.currentTimeMillis(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to (owningApp ?: ""),
            FIELD_CAPTURE_MODE to captureMode
        )
    }

    /**
     * TCP flags live in a single byte 13 bytes into the TCP header (RFC 9293 §3.1):
     * bit 0=FIN, 1=SYN, 2=RST, 3=PSH, 4=ACK, 5=URG (bits 6-7 are ECE/CWR, not used
     * by any detector here). Space-separated names, since AnomalyDetector/RuleEngine's
     * flags.contains("SYN")-style checks are shared across both capture modes.
     */
    private fun extractTcpFlags(packet: ByteArray, tcpHeaderStart: Int): String {
        val flagsOffset = tcpHeaderStart + 13
        if (flagsOffset >= packet.size) return ""
        val flagsByte = packet[flagsOffset].toInt() and 0xFF
        return buildString {
            if (flagsByte and 0x02 != 0) append("SYN ")
            if (flagsByte and 0x10 != 0) append("ACK ")
            if (flagsByte and 0x01 != 0) append("FIN ")
            if (flagsByte and 0x04 != 0) append("RST ")
            if (flagsByte and 0x08 != 0) append("PSH ")
            if (flagsByte and 0x20 != 0) append("URG ")
        }
    }

    /**
     * IPv6 fixed header is always exactly 40 bytes (RFC 8200 §3):
     * version/traffic-class/flow-label (4) | payload length (2) | next header (1)
     * | hop limit (1) | source (16) | destination (16).
     *
     * Extension headers (hop-by-hop, routing, fragment, etc.) aren't walked here —
     * "next header" is treated as the transport protocol directly, which covers the
     * overwhelming majority of real traffic (plain TCP/UDP/ICMPv6).
     */
    private fun parseIpv6Packet(
        packet: ByteArray,
        isOutgoing: Boolean,
        captureMode: String,
        resolver: OwningAppResolver?
    ): Map<String, Any>? {
        if (packet.size < 40) return null

        val nextHeader = packet[6].toInt() and 0xFF
        val sourceIP = formatIpv6Address(packet, 8)
        val destIP = formatIpv6Address(packet, 24)

        val protocolName: String
        var sourcePort = 0
        var destPort = 0
        var tcpFlags = ""

        if (40 + 4 <= packet.size) {
            when (nextHeader) {
                6 -> {
                    protocolName = "TCP"
                    sourcePort = ((packet[40].toInt() and 0xFF) shl 8) or (packet[41].toInt() and 0xFF)
                    destPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                    tcpFlags = extractTcpFlags(packet, 40)
                }
                17 -> {
                    protocolName = "UDP"
                    sourcePort = ((packet[40].toInt() and 0xFF) shl 8) or (packet[41].toInt() and 0xFF)
                    destPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                }
                58 -> protocolName = "ICMPv6"
                else -> protocolName = "Other($nextHeader)"
            }
        } else {
            protocolName = when (nextHeader) {
                6 -> "TCP"
                17 -> "UDP"
                58 -> "ICMPv6"
                else -> "Other($nextHeader)"
            }
        }

        val appName = getApplicationName(protocolName, if (isOutgoing) destPort else sourcePort)
        val owningApp = if (nextHeader == 6 || nextHeader == 17) {
            resolver?.resolve(nextHeader, isOutgoing, sourceIP, sourcePort, destIP, destPort)
        } else null

        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to System.currentTimeMillis(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to (owningApp ?: ""),
            FIELD_CAPTURE_MODE to captureMode
        )
    }

    /** Formats 16 raw bytes starting at [offset] as a zero-compressed IPv6 address string. */
    private fun formatIpv6Address(packet: ByteArray, offset: Int): String {
        val groups = IntArray(8) { i ->
            ((packet[offset + i * 2].toInt() and 0xFF) shl 8) or (packet[offset + i * 2 + 1].toInt() and 0xFF)
        }

        // Find the longest run of consecutive zero groups (min length 2) to compress with "::".
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for (i in 0..8) {
            val isZero = i < 8 && groups[i] == 0
            if (isZero) {
                if (curStart == -1) curStart = i
                curLen++
            } else {
                if (curLen > bestLen) {
                    bestStart = curStart
                    bestLen = curLen
                }
                curStart = -1
                curLen = 0
            }
        }
        if (bestLen < 2) bestStart = -1 // no worthwhile run to compress

        val sb = StringBuilder()
        var i = 0
        while (i < 8) {
            if (i == bestStart) {
                sb.append("::")
                i += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
            sb.append(Integer.toHexString(groups[i]))
            i++
        }
        return sb.toString()
    }

    private fun getApplicationName(protocol: String, port: Int): String {
        return when {
            // Web protocols
            protocol == "TCP" && port == 443 -> "HTTPS"
            protocol == "TCP" && port == 80 -> "HTTP"
            protocol == "TCP" && port == 8080 -> "HTTP-Proxy"
            protocol == "TCP" && port == 8443 -> "HTTPS-Alt"

            // DNS
            protocol == "UDP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 853 -> "DNS-over-TLS"
            protocol == "UDP" && port == 853 -> "DNS-over-TLS"

            // QUIC/HTTP3
            protocol == "UDP" && port == 443 -> "QUIC/HTTP3"

            // Email
            protocol == "TCP" && port == 25 -> "SMTP"
            protocol == "TCP" && port == 587 -> "SMTP-Secure"
            protocol == "TCP" && port == 465 -> "SMTPS"
            protocol == "TCP" && port == 110 -> "POP3"
            protocol == "TCP" && port == 995 -> "POP3S"
            protocol == "TCP" && port == 143 -> "IMAP"
            protocol == "TCP" && port == 993 -> "IMAPS"

            // File transfer
            protocol == "TCP" && port == 21 -> "FTP"
            protocol == "TCP" && port == 22 -> "SSH/SFTP"
            protocol == "TCP" && port == 990 -> "FTPS"

            // Remote access
            protocol == "TCP" && port == 23 -> "Telnet"
            protocol == "TCP" && port == 3389 -> "RDP"
            protocol == "TCP" && port == 5900 -> "VNC"

            // Database
            protocol == "TCP" && port == 3306 -> "MySQL"
            protocol == "TCP" && port == 5432 -> "PostgreSQL"
            protocol == "TCP" && port == 27017 -> "MongoDB"
            protocol == "TCP" && port == 6379 -> "Redis"

            // Messaging & VoIP
            protocol == "TCP" && port == 5222 -> "XMPP"
            protocol == "TCP" && port == 5223 -> "XMPP-SSL"
            protocol == "UDP" && port == 5060 -> "SIP"
            protocol == "TCP" && port == 5060 -> "SIP"
            protocol == "UDP" && (port in 10000..20000) -> "RTP/Media"

            // Gaming & Streaming
            protocol == "TCP" && port == 1935 -> "RTMP"
            protocol == "UDP" && port == 1935 -> "RTMP"

            // Other common services
            protocol == "TCP" && port == 119 -> "NNTP"
            protocol == "TCP" && port == 194 -> "IRC"
            protocol == "UDP" && port == 123 -> "NTP"
            protocol == "TCP" && port == 179 -> "BGP"
            protocol == "UDP" && port == 161 -> "SNMP"
            protocol == "UDP" && port == 162 -> "SNMP-Trap"

            // Default
            else -> protocol
        }
    }
}
