package com.example.packet_analyzer

/**
 * The per-packet analysis path shared by every capture back-end: payload extraction, DPI,
 * domain enrichment, then detection. It holds no Android dependencies so the evaluation
 * harness can replay captures through exactly this code on a desktop JVM or under app_process.
 */
object PacketPipeline {

    /** Returns the enriched record and the transport payload that detection should see. */
    fun dissectAndEnrich(packetInfo: Map<String, Any>, rawPacket: ByteArray?): Pair<MutableMap<String, Any>, ByteArray?> {
        var extractedPayload: ByteArray? = null
        val enrichedPacket = if (rawPacket != null && rawPacket.isNotEmpty()) {
            extractedPayload = extractPayload(rawPacket, packetInfo)
            PacketDissector.dissect(packetInfo, extractedPayload)
        } else {
            packetInfo
        }

        val finalPacket = enrichedPacket.toMutableMap()
        // Try both field name variants
        val destIp = (enrichedPacket["destinationAddress"] ?: enrichedPacket["destinationIp"]) as? String
        val sourceIp = (enrichedPacket["sourceAddress"] ?: enrichedPacket["sourceIp"]) as? String

        // A name the dissector read from this very packet (DNS question, TLS SNI) outranks
        // whatever the destination IP last resolved from.
        if (destIp != null) {
            val domain = (finalPacket["domain"] as? String) ?: DomainTracker.getDomainForIp(destIp)
            if (domain != null) {
                finalPacket["domain"] = domain
                finalPacket["domainFriendly"] = DomainTracker.getFriendlyName(domain)
            }
        }

        // Check if source IP has a known domain (for incoming traffic)
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

            // Detect IP version
            val version = (packet[0].toInt() and 0xF0) shr 4

            val ipHeaderLen = when (version) {
                4 -> {
                    // IPv4: Get IHL (Internet Header Length)
                    (packet[0].toInt() and 0x0F) * 4
                }
                6 -> {
                    // IPv6: Fixed header is always 40 bytes
                    40
                }
                else -> return null
            }

            val protocol = packetInfo["protocol"] as? String ?: return null

            // Get the underlying transport protocol
            val transportProtocol = when (protocol) {
                "HTTP", "HTTPS", "FTP", "SSH", "Telnet", "SMTP", "POP3", "IMAP", "IMAPS", "POP3S", "HTTP-Alt" -> "TCP"
                "DNS", "DHCP", "NTP", "SNMP", "SNMP-Trap", "QUIC/HTTP3", "DNS-over-TLS", "mDNS" -> "UDP"
                else -> {
                    // Handle IPv6 protocol names like "IPv6-TCP", "IPv6-UDP"
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
                    // TCP header is at least 20 bytes
                    if (packet.size < ipHeaderLen + 20) return null
                    val tcpHeaderLen = ((packet[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4
                    ipHeaderLen + tcpHeaderLen
                }
                "UDP" -> {
                    // UDP header is 8 bytes
                    ipHeaderLen + 8
                }
                "ICMP", "ICMPv6" -> {
                    // ICMP header is at least 8 bytes
                    ipHeaderLen + 8
                }
                else -> return null
            }

            if (payloadStart >= packet.size) {
                return null
            }

            return packet.copyOfRange(payloadStart, packet.size)
        } catch (e: Exception) {
            return null
        }
    }
}
