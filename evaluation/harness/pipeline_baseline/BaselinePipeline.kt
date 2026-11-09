package com.andronet.eval

import com.example.packet_analyzer.AnomalyDetector
import com.example.packet_analyzer.DomainTracker
import com.example.packet_analyzer.EvalClock
import com.example.packet_analyzer.PacketDissector
import com.example.packet_analyzer.TrafficStatistics

/**
 * Per-packet path of the code as submitted for review (git HEAD, app version 1.3.0).
 *
 * parseIpv4/parseIpv6/extractTcpFlags/getApplicationName are copied from ZdtunVpnService and
 * extractPayload plus the process() sequence from PacketAnalysisManager.processPacket, because
 * those live in classes that need a running Android service. Owning-app lookup is omitted since
 * it needs a ConnectivityManager and no detector reads it. In this version ARP never reaches the
 * pipeline (TUN carries no link layer and libpcap_capture.c drops non-IP frames), so ARP frames
 * are dropped here as well.
 */
object Pipeline {
    const val NAME = "baseline-v1.3.0"

    fun reset() {
        AnomalyDetector.reset()
        com.example.packet_analyzer.RuleEngine.clearState()
        AnomalyDetector.adaptiveThresholds.reset()
        DomainTracker.clear()
        TrafficStatistics.reset()
    }

    fun buildRecord(unit: NetUnit, outgoing: Boolean, view: String): Map<String, Any>? {
        if (unit !is NetUnit.Ip) return null
        return parsePacket(unit.packet, outgoing)
    }

    fun rawOf(unit: NetUnit): ByteArray? = (unit as? NetUnit.Ip)?.packet

    fun dissectAndEnrich(packetInfo: Map<String, Any>, rawPacket: ByteArray?): Pair<MutableMap<String, Any>, ByteArray?> {
        var extractedPayload: ByteArray? = null
        val enrichedPacket = if (rawPacket != null && rawPacket.isNotEmpty()) {
            extractedPayload = extractPayload(rawPacket, packetInfo)
            PacketDissector.dissect(packetInfo, extractedPayload)
        } else {
            packetInfo
        }

        val finalPacket = enrichedPacket.toMutableMap()
        val destIp = (enrichedPacket["destinationAddress"] ?: enrichedPacket["destinationIp"]) as? String
        val sourceIp = (enrichedPacket["sourceAddress"] ?: enrichedPacket["sourceIp"]) as? String
        if (destIp != null) {
            val domain = DomainTracker.getDomainForIp(destIp)
            if (domain != null) {
                finalPacket["domain"] = domain
                finalPacket["domainFriendly"] = DomainTracker.getFriendlyName(domain)
            }
        }
        if (sourceIp != null) {
            val sourceDomain = DomainTracker.getDomainForIp(sourceIp)
            if (sourceDomain != null) {
                finalPacket["sourceDomain"] = sourceDomain
            }
        }
        return Pair(finalPacket, extractedPayload)
    }

    fun analyze(finalPacket: MutableMap<String, Any>, payload: ByteArray?) {
        AnomalyDetector.analyzePacket(finalPacket, payload)
        finalPacket["anomalyScore"] = AnomalyDetector.calculateAnomalyScore(finalPacket)
    }

    private fun extractPayload(packet: ByteArray, packetInfo: Map<String, Any>): ByteArray? {
        try {
            if (packet.size < 20) return null
            val version = (packet[0].toInt() and 0xF0) shr 4
            val ipHeaderLen = when (version) {
                4 -> (packet[0].toInt() and 0x0F) * 4
                6 -> 40
                else -> return null
            }
            val protocol = packetInfo["protocol"] as? String ?: return null
            val transportProtocol = when (protocol) {
                "HTTP", "HTTPS", "FTP", "SSH", "Telnet", "SMTP", "POP3", "IMAP", "IMAPS", "POP3S", "HTTP-Alt" -> "TCP"
                "DNS", "DHCP", "NTP", "SNMP", "SNMP-Trap", "QUIC/HTTP3", "DNS-over-TLS", "mDNS" -> "UDP"
                else -> {
                    when {
                        protocol.contains("TCP", ignoreCase = true) -> "TCP"
                        protocol.contains("UDP", ignoreCase = true) -> "UDP"
                        protocol.contains("ICMP", ignoreCase = true) -> "ICMP"
                        else -> protocol
                    }
                }
            }
            val payloadStart = when (transportProtocol) {
                "TCP" -> {
                    if (packet.size < ipHeaderLen + 20) return null
                    val tcpHeaderLen = ((packet[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4
                    ipHeaderLen + tcpHeaderLen
                }
                "UDP" -> ipHeaderLen + 8
                "ICMP", "ICMPv6" -> ipHeaderLen + 8
                else -> return null
            }
            if (payloadStart >= packet.size) return null
            return packet.copyOfRange(payloadStart, packet.size)
        } catch (e: Exception) {
            return null
        }
    }

    private fun parsePacket(packet: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
        return try {
            if (packet.isEmpty()) return null
            when ((packet[0].toInt() shr 4) and 0x0F) {
                4 -> parseIpv4Packet(packet, isOutgoing)
                6 -> parseIpv6Packet(packet, isOutgoing)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun parseIpv4Packet(packet: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
        if (packet.size < 20) return null
        val protocol = packet[9].toInt() and 0xFF
        val sourceIP = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}." +
            "${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
        val destIP = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}." +
            "${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > packet.size) return null
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
        val appName = getApplicationName(protocolName, if (isOutgoing) destPort else sourcePort)
        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to EvalClock.now(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to ""
        )
    }

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

    private fun parseIpv6Packet(packet: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
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
        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to EvalClock.now(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to ""
        )
    }

    private fun formatIpv6Address(packet: ByteArray, offset: Int): String {
        val groups = IntArray(8) { i ->
            ((packet[offset + i * 2].toInt() and 0xFF) shl 8) or (packet[offset + i * 2 + 1].toInt() and 0xFF)
        }
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
        if (bestLen < 2) bestStart = -1
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
            protocol == "TCP" && port == 443 -> "HTTPS"
            protocol == "TCP" && port == 80 -> "HTTP"
            protocol == "TCP" && port == 8080 -> "HTTP-Proxy"
            protocol == "TCP" && port == 8443 -> "HTTPS-Alt"
            protocol == "UDP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 853 -> "DNS-over-TLS"
            protocol == "UDP" && port == 853 -> "DNS-over-TLS"
            protocol == "UDP" && port == 443 -> "QUIC/HTTP3"
            protocol == "TCP" && port == 25 -> "SMTP"
            protocol == "TCP" && port == 587 -> "SMTP-Secure"
            protocol == "TCP" && port == 465 -> "SMTPS"
            protocol == "TCP" && port == 110 -> "POP3"
            protocol == "TCP" && port == 995 -> "POP3S"
            protocol == "TCP" && port == 143 -> "IMAP"
            protocol == "TCP" && port == 993 -> "IMAPS"
            protocol == "TCP" && port == 21 -> "FTP"
            protocol == "TCP" && port == 22 -> "SSH/SFTP"
            protocol == "TCP" && port == 990 -> "FTPS"
            protocol == "TCP" && port == 23 -> "Telnet"
            protocol == "TCP" && port == 3389 -> "RDP"
            protocol == "TCP" && port == 5900 -> "VNC"
            protocol == "TCP" && port == 3306 -> "MySQL"
            protocol == "TCP" && port == 5432 -> "PostgreSQL"
            protocol == "TCP" && port == 27017 -> "MongoDB"
            protocol == "TCP" && port == 6379 -> "Redis"
            protocol == "TCP" && port == 5222 -> "XMPP"
            protocol == "TCP" && port == 5223 -> "XMPP-SSL"
            protocol == "UDP" && port == 5060 -> "SIP"
            protocol == "TCP" && port == 5060 -> "SIP"
            protocol == "UDP" && (port in 10000..20000) -> "RTP/Media"
            protocol == "TCP" && port == 1935 -> "RTMP"
            protocol == "UDP" && port == 1935 -> "RTMP"
            protocol == "TCP" && port == 119 -> "NNTP"
            protocol == "TCP" && port == 194 -> "IRC"
            protocol == "UDP" && port == 123 -> "NTP"
            protocol == "TCP" && port == 179 -> "BGP"
            protocol == "UDP" && port == 161 -> "SNMP"
            protocol == "UDP" && port == 162 -> "SNMP-Trap"
            else -> protocol
        }
    }
}
