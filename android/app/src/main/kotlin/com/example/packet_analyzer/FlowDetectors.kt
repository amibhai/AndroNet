package com.example.packet_analyzer

import kotlin.math.abs

/**
 * Detection that works without reading encrypted content, from what a flow shows at its start and in
 * its timing. These cost almost nothing, since most run once per flow, and they cover the traffic the
 * payload layers have to skip.
 */
object FlowDetectors {
    private const val MIN_OPAQUE_PAYLOAD = 16
    private const val MIN_PROTOCOL_PAYLOAD = 8

    // Wu et al., USENIX Security 2023: the exemptions the Great Firewall uses to tell fully encrypted
    // traffic from everything else. Bits set per byte stays near 4 only in uniformly random data.
    private const val POPCOUNT_LOW = 3.4
    private const val POPCOUNT_HIGH = 4.6
    private const val PRINTABLE_PREFIX = 6
    private const val PRINTABLE_RUN = 20

    private const val PORT_SSH = 22
    private const val PORT_DNS = 53
    private const val PORT_HTTP = 80

    // WhatsApp and Telegram run their own encrypted protocols on the XMPP port, so opacity says nothing there
    private const val PORT_XMPP = 5222

    // Beaconing: an implant checking in on a timer. Gaps between activity bursts to one destination
    // are nearly equal, where traffic driven by people or by events is not.
    private const val BURST_GAP_MS = 1_000L
    private const val BEACON_GAPS = 16
    private const val BEACON_MIN_GAPS = 12
    private const val BEACON_MIN_PERIOD_MS = 10_000.0
    private const val BEACON_MAX_PERIOD_MS = 600_000.0
    private const val BEACON_MAX_VARIATION = 0.1
    private const val REPORT_INTERVAL_MS = 3_600_000L
    private const val MAX_BEACON_KEYS = 1024
    private const val MAX_REPORT_KEYS = 1024

    private const val DNS_WINDOW_MS = 60_000L
    private const val TXT_MIN_ANSWER_BYTES = 100
    private const val TXT_ANSWERS_LIMIT = 3
    private const val NXDOMAIN_LIMIT = 20
    private const val MAX_DNS_KEYS = 256

    private class BeaconState {
        val gaps = LongArray(BEACON_GAPS)
        var filled = 0
        var next = 0
        var lastPacket = 0L
        var lastBurst = 0L
        var named = false
    }

    private class Burst {
        var windowStart = 0L
        var count = 0
    }

    private class FailedNames {
        var windowStart = 0L
        val names = HashSet<String>()
    }

    private val beacons = lru<BeaconState>(MAX_BEACON_KEYS)
    private val txtChannels = lru<Burst>(MAX_DNS_KEYS)
    private val nxBursts = lru<FailedNames>(MAX_DNS_KEYS)
    private val lastReports = lru<Long>(MAX_REPORT_KEYS)

    private fun <T> lru(max: Int) = object : LinkedHashMap<String, T>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, T>?) = size > max
    }

    fun reset() {
        beacons.clear()
        txtChannels.clear()
        nxBursts.clear()
        lastReports.clear()
    }

    // One report per app, finding and port an hour is enough to act on, and an app that reconnects
    // all day cannot bury what the others do
    private fun firstThisHour(id: String, packetInfo: Map<String, Any>, target: String): Boolean {
        val now = PacketClock.now()
        val key = "$id|${AppContext.principal(packetInfo)}|$target"
        val last = lastReports[key]
        if (last != null && now - last < REPORT_INTERVAL_MS) return false
        lastReports[key] = now
        return true
    }

    fun inspect(packetInfo: Map<String, Any>, payload: ByteArray?, report: (AnomalyDetector.Anomaly) -> Unit) {
        val protocol = packetInfo["protocol"] as? String ?: return
        val tcp = protocol.contains("TCP")
        if (tcp && packetInfo["firstPayload"] == true && payload != null) checkFirstPayload(packetInfo, payload, report)
        if (tcp) checkTlsFingerprint(packetInfo, report)
        if (tcp || protocol.contains("UDP")) trackBeacon(packetInfo, payload, report)
        checkDnsResponse(packetInfo, report)
    }

    // === What a flow says first ===

    /** True for bytes that look uniformly random: no printable text and no known protocol's start. */
    internal fun isOpaque(p: ByteArray): Boolean {
        if (p.size < MIN_OPAQUE_PAYLOAD) return false
        var bits = 0
        var printable = 0
        var run = 0
        var longestRun = 0
        for (b in p) {
            val v = b.toInt() and 0xFF
            bits += Integer.bitCount(v)
            if (v in 0x20..0x7E) {
                printable++
                run++
                if (run > longestRun) longestRun = run
            } else {
                run = 0
            }
        }
        val popcount = bits.toDouble() / p.size
        if (popcount <= POPCOUNT_LOW || popcount >= POPCOUNT_HIGH) return false
        if ((0 until PRINTABLE_PREFIX).all { (p[it].toInt() and 0xFF) in 0x20..0x7E }) return false
        if (printable * 2 > p.size) return false
        if (longestRun > PRINTABLE_RUN) return false
        return !looksLikeTls(p) && !PacketDissector.looksLikeHttp(p)
    }

    private fun looksLikeTls(p: ByteArray): Boolean =
        p.size >= 3 && (p[0].toInt() and 0xFF) in 20..23 && p[1].toInt() == 3 && (p[2].toInt() and 0xFF) <= 4

    /** Does a first payload on this well-known port speak that port's protocol? Null for other ports. */
    internal fun speaksPortProtocol(port: Int, p: ByteArray): Boolean? = when (port) {
        PORT_SSH -> String(p, 0, minOf(p.size, 4), Charsets.ISO_8859_1) == "SSH-"
        PORT_HTTP -> PacketDissector.looksLikeHttp(p)
        PORT_DNS -> looksLikeTcpDns(p)
        else -> null
    }

    // A two-byte length, then a DNS header holding one question. Long messages continue in later
    // segments, so the length may exceed this payload, within reason.
    private fun looksLikeTcpDns(p: ByteArray): Boolean {
        if (p.size < 14) return false
        val length = ((p[0].toInt() and 0xFF) shl 8) or (p[1].toInt() and 0xFF)
        val questions = ((p[6].toInt() and 0xFF) shl 8) or (p[7].toInt() and 0xFF)
        return length >= p.size - 2 && length < 16384 && questions == 1
    }

    private fun checkFirstPayload(packetInfo: Map<String, Any>, payload: ByteArray, report: (AnomalyDetector.Anomaly) -> Unit) {
        val sourcePort = packetInfo["sourcePort"] as? Int ?: return
        val destPort = packetInfo["destinationPort"] as? Int ?: return
        val sourceIp = packetInfo["sourceIp"] as? String
        val destIp = packetInfo["destinationIp"] as? String

        val servicePort = listOf(destPort, sourcePort).firstOrNull { speaksPortProtocol(it, payload) != null }
        if (servicePort != null) {
            if (payload.size >= MIN_PROTOCOL_PAYLOAD && speaksPortProtocol(servicePort, payload) == false &&
                firstThisHour("FLOW-002", packetInfo, "$servicePort")
            ) {
                report(
                    AnomalyDetector.Anomaly(
                        AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC, AnomalyDetector.Severity.MEDIUM,
                        "[FLOW-002] Protocol mismatch: traffic on port $servicePort does not speak that port's protocol",
                        sourceIp, destIp
                    )
                )
            }
            return
        }
        if (destPort in PacketDissector.ENCRYPTED_PORTS || sourcePort in PacketDissector.ENCRYPTED_PORTS) return
        if (destPort == PORT_XMPP || sourcePort == PORT_XMPP) return
        if (isOpaque(payload) && firstThisHour("FLOW-001", packetInfo, "$destPort")) {
            report(
                AnomalyDetector.Anomaly(
                    AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC, AnomalyDetector.Severity.MEDIUM,
                    "[FLOW-001] Opaque flow: first payload on port $destPort looks fully encrypted and matches no known protocol",
                    sourceIp, destIp
                )
            )
        }
    }

    // === TLS without decryption ===

    private fun checkTlsFingerprint(packetInfo: Map<String, Any>, report: (AnomalyDetector.Anomaly) -> Unit) {
        @Suppress("UNCHECKED_CAST")
        val tls = packetInfo["tlsData"] as? Map<String, String> ?: return
        val ja4 = tls["ja4"] ?: return
        // A library keeps its cipher list, while ALPN and resumption change the rest of JA4 from one
        // connection to the next: 27 JA4 values in one phone session came from 4 cipher lists
        val cipherList = ja4.split('_').getOrNull(1) ?: return
        val app = AppContext.app(packetInfo)
        if (app.isNotEmpty() && AppProfiles.observeHello(app, cipherList)) {
            report(
                AnomalyDetector.Anomaly(
                    AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC, AnomalyDetector.Severity.MEDIUM,
                    "[APP-001] New TLS library from a settled app: $ja4",
                    packetInfo["sourceIp"] as? String, packetInfo["destinationIp"] as? String
                )
            )
        }
    }

    // === Timing ===

    private fun trackBeacon(packetInfo: Map<String, Any>, payload: ByteArray?, report: (AnomalyDetector.Anomaly) -> Unit) {
        if (packetInfo["direction"] != "outgoing") return
        val size = (packetInfo["payloadSize"] as? Int) ?: payload?.size ?: 0
        if (size == 0) return
        val destIp = packetInfo["destinationIp"] as? String ?: return
        val destPort = packetInfo["destinationPort"] as? Int ?: return
        if (destPort == PORT_DNS) return
        // QUIC keeps its connections alive with a steady ping, whoever owns them
        if ((packetInfo["protocol"] as? String)?.contains("UDP") == true && destPort in PacketDissector.ENCRYPTED_PORTS) return

        val now = PacketClock.now()
        val state = beacons.getOrPut("${AppContext.principal(packetInfo)}|$destIp:$destPort") { BeaconState() }
        // Connections outlive the DNS entry that named their address, so a name once seen stays good
        if (packetInfo["domain"] != null) state.named = true
        val startsBurst = state.lastPacket != 0L && now - state.lastPacket >= BURST_GAP_MS
        if (state.lastPacket == 0L) state.lastBurst = now
        state.lastPacket = now
        if (!startsBurst) return

        state.gaps[state.next] = now - state.lastBurst
        state.next = (state.next + 1) % BEACON_GAPS
        if (state.filled < BEACON_GAPS) state.filled++
        state.lastBurst = now

        if (state.filled < BEACON_MIN_GAPS || !isPeriodic(state)) return
        // Push services hold periodic connections too, but they are reached through a DNS name.
        // An implant dialling a bare address on a timer has no such explanation.
        if (state.named) return
        if (!firstThisHour("FLOW-003", packetInfo, "$destIp:$destPort")) return
        report(
            AnomalyDetector.Anomaly(
                AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC, AnomalyDetector.Severity.MEDIUM,
                "[FLOW-003] Beaconing: regular check-ins to $destIp:$destPort, which no DNS name explains",
                packetInfo["sourceIp"] as? String, destIp
            )
        )
    }

    // Measured against the median, so that one long pause or one large upload cannot hide a timer
    private fun isPeriodic(state: BeaconState): Boolean {
        val gaps = state.gaps.copyOf(state.filled).also { it.sort() }
        val median = gaps[gaps.size / 2].toDouble()
        if (median < BEACON_MIN_PERIOD_MS || median > BEACON_MAX_PERIOD_MS) return false
        val nearMedian = gaps.count { abs(it - median) <= median * BEACON_MAX_VARIATION }
        return nearMedian * 4 >= gaps.size * 3
    }

    // === DNS answers ===

    private fun checkDnsResponse(packetInfo: Map<String, Any>, report: (AnomalyDetector.Anomaly) -> Unit) {
        @Suppress("UNCHECKED_CAST")
        val dns = packetInfo["dnsData"] as? Map<String, String> ?: return
        if (dns["type"] != "Response") return
        val now = PacketClock.now()
        val sourceIp = packetInfo["sourceIp"] as? String
        val destIp = packetInfo["destinationIp"] as? String
        val name = dns["queryName"] ?: ""

        // Commands fit in TXT answers, and query names can stay short and innocent looking
        if (dns["queryType"] == "TXT" && (dns["answerBytes"]?.toIntOrNull() ?: 0) >= TXT_MIN_ANSWER_BYTES) {
            val zone = name.split('.').takeLast(2).joinToString(".")
            if (countInWindow(txtChannels, zone, now) >= TXT_ANSWERS_LIMIT) {
                report(
                    AnomalyDetector.Anomaly(
                        AnomalyDetector.AnomalyType.DNS_TUNNELING, AnomalyDetector.Severity.HIGH,
                        "[FLOW-004] Repeated large TXT answers from $zone: possible DNS command channel", sourceIp, destIp
                    )
                )
            }
        }
        // Domain-generation malware tries many names until one resolves. Distinct names, since a page
        // retrying one blocked advertising host many times generates nothing.
        if (dns["responseCode"]?.startsWith("Name Error") == true) {
            val failed = nxBursts.getOrPut(AppContext.principal(packetInfo)) { FailedNames() }
            if (now - failed.windowStart > DNS_WINDOW_MS) {
                failed.windowStart = now
                failed.names.clear()
            }
            if (failed.names.size < NXDOMAIN_LIMIT) failed.names.add(name)
            if (failed.names.size >= NXDOMAIN_LIMIT) {
                report(
                    AnomalyDetector.Anomaly(
                        AnomalyDetector.AnomalyType.DNS_TUNNELING, AnomalyDetector.Severity.MEDIUM,
                        "[FLOW-005] Burst of failed DNS lookups: possible domain generation", sourceIp, destIp
                    )
                )
            }
        }
    }

    private fun countInWindow(table: MutableMap<String, Burst>, key: String, now: Long): Int {
        val burst = table.getOrPut(key) { Burst() }
        if (now - burst.windowStart > DNS_WINDOW_MS) {
            burst.windowStart = now
            burst.count = 0
        }
        burst.count++
        return burst.count
    }
}
