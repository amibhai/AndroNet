package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.log2

/**
 * Network Anomaly Detection System
 * Detects port scans, ARP spoofing, DDoS attacks, and other suspicious activities
 */
object AnomalyDetector {
    private const val TAG = "AnomalyDetector"

    // Detection threshold floor values — adaptive values take precedence at runtime
    private const val FLOOR_PORT_SCAN = 20
    private const val PORT_SCAN_WINDOW_MS = 10000L
    private const val FLOOR_SYN_FLOOD = 100
    private const val FLOOR_CONNECTION_RATE = 50
    private const val DNS_QUERY_THRESHOLD = 30

    // Entropy analysis thresholds
    // COMMIT 1: raised to reduce false positives from compressed media and modern compression
    private const val ENTROPY_THRESHOLD_HIGH = 7.6
    private const val ENTROPY_THRESHOLD_SUSPICIOUS = 7.2
    private const val ENTROPY_THRESHOLD_DNS_TUNNEL = 6.2
    private const val MIN_PAYLOAD_SIZE_FOR_ENTROPY = 64

    // COMMIT 1: protocol allowlist — these always produce high entropy legitimately
    private val ENTROPY_ALLOWLIST = setOf(
        "TLS", "QUIC", "HTTPS", "SSL",
        "DTLS",
        "WireGuard",
        "IPSec",
        "SSH",
        "SFTP",
        "FTPS",
        "SMTPS",
        "IMAPS",
        "POP3S",
        "DoT",
        "DoH",
        "SRTP",
        "ZRTP"
    )

    // COMMIT 2: cooldown — prevents the same source IP from flooding the alert log
    private val entropyAlertCooldown = ConcurrentHashMap<String, Long>()
    private const val ENTROPY_COOLDOWN_MS = 30_000L

    // COMMIT 3: consecutive high-entropy packet counters — one-off packets are not evidence
    private val highEntropyPacketCount = ConcurrentHashMap<String, Int>()
    private val dnsHighEntropyCount = ConcurrentHashMap<String, Int>()
    private const val ENTROPY_CONSECUTIVE_THRESHOLD = 5
    private const val DNS_ENTROPY_CONSECUTIVE_THRESHOLD = 3

    // COMMIT 2: packet counter drives periodic cooldown map cleanup
    private val packetCount = AtomicInteger(0)

    // Repeats of one finding about one host collapse into a single alert per window, the same
    // aggregation Snort calls event filtering. Without it a tunnel raises one alert per query.
    private val alertSuppression = ConcurrentHashMap<String, Long>()
    private const val ALERT_SUPPRESS_MS = 10_000L

    // The app behind the packet being analysed; analysis runs on one thread
    private var currentApp = ""

    private const val HLL_REGISTERS = 256
    private const val MAX_FLOOD_TARGETS = 64
    private const val DISTRIBUTED_FLOOD_PACKETS = 300
    private const val DISTRIBUTED_SOURCE_SHARE = 0.5
    private const val ARP_MAC_WINDOW_MS = 60_000L
    private const val MAX_ARP_ENTRIES = 4096
    private const val DNS_LONG_NAME = 50
    private const val DNS_ZONE_WINDOW_MS = 60_000L
    private const val DNS_ZONE_LONG_NAMES = 10L
    private const val MAX_DNS_ZONES = 256

    // Peak per-window counts since the last adaptive sample
    private val peakPorts = AtomicInteger(0)
    private val peakSyn = AtomicInteger(0)
    private val peakConnections = AtomicInteger(0)
    @Volatile private var lastAdaptiveSample = 0L
    private const val ADAPTIVE_SAMPLE_MS = 1_000L

    // COMMIT 7: adaptive thresholds replace all hard-coded comparison values
    val adaptiveThresholds = AdaptiveThresholdManager()

    // ML-based data structures
    private val trafficStats = TrafficStatistics()
    private val behavioralAnalyzer = BehavioralAnalyzer()
    private val entropyAnalyzer = EntropyAnalyzer()
    private val connectionPatternAnalyzer = ConnectionPatternAnalyzer()

    private data class StatisticalModel(
        var mean: Double = 0.0,
        var variance: Double = 0.0,
        var count: Int = 0,
        var lastUpdate: Long = PacketClock.now()
    )

    private data class TrafficStatistics(
        val packetSizeStats: StatisticalModel = StatisticalModel()
    )

    private data class BehavioralAnalyzer(
        val ipActivityMap: MutableMap<String, MutableList<Long>> = mutableMapOf(),
        val protocolUsageMap: MutableMap<String, MutableList<Long>> = mutableMapOf(),
        val portActivityMap: MutableMap<Int, MutableList<Long>> = mutableMapOf()
    )

    private data class EntropyAnalyzer(
        val payloadEntropyMap: MutableMap<String, MutableList<Double>> = mutableMapOf(),
        val averageEntropy: Double = 4.5
    )

    private data class ConnectionPatternAnalyzer(
        val connectionSequences: MutableMap<String, MutableList<String>> = mutableMapOf(),
        val timingPatterns: MutableMap<String, MutableList<Long>> = mutableMapOf()
    )

    // Trackers — ConcurrentHashMap because analyzePacket runs on IO/Default coroutines
    private val anomalyListeners = CopyOnWriteArrayList<(Anomaly) -> Unit>()
    private val portScans = ConcurrentHashMap<String, PortScanTracker>()
    private val synFloodTracker = ConcurrentHashMap<String, SynFloodTracker>()
    private val connectionTracker = ConcurrentHashMap<String, ConnectionRateTracker>()
    private val arpCache = ConcurrentHashMap<String, String>()
    private val macClaims = ConcurrentHashMap<String, ConcurrentHashMap<String, Long>>()
    private val longNames = object : LinkedHashMap<String, LongArray>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, LongArray>?) = size > MAX_DNS_ZONES
    }
    private val dnsQueryTracker = DnsQueryTracker()

    data class Anomaly(
        val type: AnomalyType,
        val severity: Severity,
        val description: String,
        val sourceIp: String? = null,
        val destinationIp: String? = null,
        val details: Map<String, Any> = emptyMap(),
        val timestamp: Long = PacketClock.now()
    )

    enum class AnomalyType {
        PORT_SCAN, SYN_FLOOD, ARP_SPOOFING, DNS_TUNNELING, CONNECTION_FLOOD,
        UNUSUAL_TRAFFIC, MALFORMED_PACKET, HIGH_ENTROPY_PAYLOAD, COVERT_CHANNEL, ANALYSIS_OVERLOAD,
        DISTRIBUTED_FLOOD
    }

    enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

    private data class PortScanTracker(
        var ports: MutableSet<Int> = mutableSetOf(),
        var firstSeen: Long = PacketClock.now(),
        var lastSeen: Long = PacketClock.now()
    )

    private data class SynFloodTracker(
        var synCount: Int = 0,
        var windowStart: Long = PacketClock.now()
    )

    private data class ConnectionRateTracker(
        var connections: Int = 0,
        var windowStart: Long = PacketClock.now()
    )

    private data class DnsQueryTracker(
        var queries: Int = 0,
        var windowStart: Long = PacketClock.now(),
        var domains: MutableSet<String> = mutableSetOf()
    )

    // === Listeners ===
    fun addAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.add(listener)
    }

    fun removeAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.remove(listener)
    }

    fun calculateEntropy(payload: ByteArray): Double {
        if (payload.isEmpty()) return 0.0
        val frequency = IntArray(256)
        for (byte in payload) frequency[byte.toInt() and 0xFF]++
        val size = payload.size.toDouble()
        return frequency.fold(0.0) { entropy, count ->
            if (count == 0) entropy
            else {
                val p = count / size
                entropy - p * log2(p)
            }
        }
    }

    fun calculateAnomalyScore(packetInfo: Map<String, Any>): Double {
        val sourceIp = AppContext.principal(packetInfo)
        val destIp = (packetInfo["destinationIp"] ?: packetInfo["destinationAddress"]) as? String ?: ""

        val portScanScore = portScans[sourceIp]?.let {
            (it.ports.size.toDouble() / adaptiveThresholds.portScanThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        val synFloodScore = synFloodTracker[destIp]?.let {
            (it.synCount.toDouble() / adaptiveThresholds.synFloodThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        val connectionScore = connectionTracker[sourceIp]?.let {
            (it.connections.toDouble() / adaptiveThresholds.connectionRateThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        return (portScanScore * 0.3 + synFloodScore * 0.4 + connectionScore * 0.3).coerceIn(0.0, 1.0)
    }

    // === Core Analysis ===
    fun analyzePacket(packetInfo: Map<String, Any>, payload: ByteArray? = null) {
        try {
            // COMMIT 2: periodic cleanup of the cooldown map to prevent unbounded growth
            if (packetCount.incrementAndGet() % 1000 == 0) clearStaleEntropyCooldowns()

            val sourceIp = packetInfo["sourceIp"] as? String ?: return
            val destIp = packetInfo["destinationIp"] as? String ?: return
            val protocol = packetInfo["protocol"] as? String ?: return
            val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
            val flags = packetInfo["flags"] as? String ?: ""
            val hasAck = flags.contains("ACK")
            val principal = AppContext.principal(packetInfo)
            currentApp = AppContext.app(packetInfo)

            // === 1. Basic Rule-Based Detection ===
            // These trackers also run during the learning period, when reportAnomaly mutes their
            // alerts: the baseline can only be learned from counters that are actually counting.
            // Probes and connection attempts leave ACK clear. Counting ACKed packets as well would
            // read a busy server's replies, each to its own ephemeral port, as a port scan.
            if (protocol == "TCP" && destPort > 0 && !hasAck) detectPortScan(principal, destPort, destIp)
            if (protocol == "TCP" && flags.contains("SYN") && !hasAck) {
                detectSynFlood(destIp)
                detectConnectionFlood(principal, AppContext.limitFactor(packetInfo))
            }
            detectDistributedFlood(sourceIp, destIp, protocol, flags)
            FlowDetectors.inspect(packetInfo, payload, ::reportAnomaly)
            sampleAdaptiveBaseline()

            // COMMIT 10: during the 60-second learning period never fire alerts,
            // which prevents the first-minute false positive flood
            if (adaptiveThresholds.isInLearningPeriod()) return

            if (protocol == "TCP" && flags.isNotEmpty()) detectMalformedTcpFlags(sourceIp, destIp, flags)
            if (protocol == "UDP" && destPort == 53) {
                val dnsData = packetInfo["dnsData"] as? Map<String, String>
                detectDnsTunneling(dnsData?.get("queryName") ?: "", sourceIp, destIp)
            }
            if (protocol == "ARP") detectArpSpoofing(packetInfo)

            // Signature and rule payload predicates skip ciphertext. Header, port, rate and
            // size predicates still apply to those packets.
            val inspectable = if (packetInfo["encrypted"] == true) null else payload

            // === 2. Signature-Based Detection ===
            val signatureMatches = SignatureDatabase.matchSignatures(packetInfo, inspectable)
            for (match in signatureMatches) {
                reportAnomaly(
                    Anomaly(
                        type = when (match.signature.category) {
                            SignatureDatabase.Category.MALWARE -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.EXPLOIT -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.RECONNAISSANCE -> AnomalyType.PORT_SCAN
                            SignatureDatabase.Category.COMMAND_CONTROL -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.DATA_EXFILTRATION -> AnomalyType.DNS_TUNNELING
                            SignatureDatabase.Category.BRUTE_FORCE -> AnomalyType.CONNECTION_FLOOD
                            SignatureDatabase.Category.WEB_ATTACK -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.NETWORK_ATTACK -> AnomalyType.SYN_FLOOD
                        },
                        severity = match.signature.severity,
                        description = "[${match.signature.id}] ${match.signature.name}: ${match.signature.description}",
                        sourceIp = sourceIp,
                        destinationIp = destIp,
                        details = mapOf(
                            "signatureId" to match.signature.id,
                            "category" to match.signature.category.name
                        )
                    )
                )
            }

            // === 3. Rule Engine Detection ===
            val ruleMatches = RuleEngine.evaluateRules(packetInfo, inspectable)
            for (match in ruleMatches) {
                reportAnomaly(
                    Anomaly(
                        type = when (match.rule.category) {
                            "RECONNAISSANCE" -> AnomalyType.PORT_SCAN
                            "WEB_ATTACK" -> AnomalyType.UNUSUAL_TRAFFIC
                            "MALWARE" -> AnomalyType.UNUSUAL_TRAFFIC
                            "EXFILTRATION" -> AnomalyType.DNS_TUNNELING
                            "BRUTE_FORCE" -> AnomalyType.CONNECTION_FLOOD
                            "EXPLOIT" -> AnomalyType.UNUSUAL_TRAFFIC
                            else -> AnomalyType.UNUSUAL_TRAFFIC
                        },
                        severity = match.rule.severity,
                        description = "[${match.rule.id}] ${match.rule.name}: ${match.rule.description}",
                        sourceIp = sourceIp,
                        destinationIp = destIp,
                        details = match.details
                    )
                )
            }

            // === 4. Entropy-Based Detection ===
            if (inspectable != null && inspectable.size >= MIN_PAYLOAD_SIZE_FOR_ENTROPY) {
                val appName = packetInfo["appName"] as? String
                val outgoing = packetInfo["direction"] == "outgoing"
                checkDnsTunneling(inspectable, appName, sourceIp, destIp)
                checkHighEntropyPayload(inspectable, protocol, appName, outgoing, sourceIp, destIp)
                (packetInfo as? MutableMap<String, Any>)?.put("entropyScore", calculateEntropy(inspectable))
            }

            // === 5. ML-Based Detection (Stubs) ===
            detectBehavioralAnomalies(packetInfo)
            detectConnectionPatternAnomalies(packetInfo)
            updateTrafficStatistics(packetInfo, payload)
            updateBehavioralModels(packetInfo)
            updateAdaptiveThresholds()

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing packet: ${e.message}")
        }
    }

    // Feeds the adaptive manager once per second with the peak count each tracker reached.
    // A per-packet sample of a counter still climbing inside its window lets an attack raise
    // its own threshold faster than the counter can reach it.
    private fun sampleAdaptiveBaseline() {
        val now = PacketClock.now()
        if (now - lastAdaptiveSample < ADAPTIVE_SAMPLE_MS) return
        lastAdaptiveSample = now
        adaptiveThresholds.recordObservation(
            portScans = peakPorts.getAndSet(0),
            synRate = peakSyn.getAndSet(0),
            connectionRate = peakConnections.getAndSet(0),
            dnsRate = getCurrentDnsRate(),
            arpRate = getCurrentArpRate()
        )
    }

    // === Basic Detection Functions ===
    private fun detectPortScan(sourceIp: String, port: Int, destIp: String) {
        val now = PacketClock.now()
        val tracker = portScans.getOrPut(sourceIp) { PortScanTracker() }

        if (now - tracker.firstSeen > PORT_SCAN_WINDOW_MS) {
            tracker.ports.clear()
            tracker.firstSeen = now
        }
        tracker.ports.add(port)
        tracker.lastSeen = now
        peakPorts.accumulateAndGet(tracker.ports.size, ::maxOf)

        // COMMIT 7: use adaptive threshold instead of hard-coded constant
        if (tracker.ports.size >= adaptiveThresholds.portScanThreshold) {
            reportAnomaly(
                Anomaly(
                    AnomalyType.PORT_SCAN, Severity.HIGH,
                    "Port scan detected from $sourceIp",
                    sourceIp, destIp
                )
            )
            tracker.ports.clear()
        }
    }

    private fun detectSynFlood(targetIp: String) {
        val now = PacketClock.now()
        val tracker = synFloodTracker.getOrPut(targetIp) { SynFloodTracker() }

        if (now - tracker.windowStart > 1000) {
            tracker.synCount = 0
            tracker.windowStart = now
        }
        tracker.synCount++
        peakSyn.accumulateAndGet(tracker.synCount, ::maxOf)
        // COMMIT 7: use adaptive threshold
        if (tracker.synCount >= adaptiveThresholds.synFloodThreshold) {
            reportAnomaly(
                Anomaly(AnomalyType.SYN_FLOOD, Severity.CRITICAL, "Possible SYN flood", destinationIp = targetIp)
            )
            tracker.synCount = 0
        }
    }

    private fun detectConnectionFlood(principal: String, limitFactor: Double) {
        val now = PacketClock.now()
        val tracker = connectionTracker.getOrPut(principal) { ConnectionRateTracker() }

        if (now - tracker.windowStart > 1000) {
            tracker.connections = 0
            tracker.windowStart = now
        }
        tracker.connections++
        peakConnections.accumulateAndGet(tracker.connections, ::maxOf)
        // COMMIT 7: use adaptive threshold
        if (tracker.connections >= adaptiveThresholds.connectionRateThreshold * limitFactor) {
            reportAnomaly(
                Anomaly(AnomalyType.CONNECTION_FLOOD, Severity.HIGH, "Connection flood detected", sourceIp = principal)
            )
            tracker.connections = 0
        }
    }

    // A spoofed flood gives every packet a new source, so no per-source count ever fills. What gives
    // it away is many packets at one target from improbably many sources. The source count is a
    // HyperLogLog sketch: constant memory, which a flood of new addresses cannot exhaust.
    private class TargetSketch {
        var windowStart = 0L
        var packets = 0
        val registers = ByteArray(HLL_REGISTERS)

        fun clear(now: Long) {
            windowStart = now
            packets = 0
            registers.fill(0)
        }

        fun add(source: String) {
            var h = source.hashCode()
            h = (h xor (h ushr 16)) * -0x7a143595
            h = (h xor (h ushr 13)) * -0x3d4d51cb
            h = h xor (h ushr 16)
            val register = h ushr 24
            val rank = (Integer.numberOfLeadingZeros(h shl 8 or 0x80) + 1).toByte()
            if (rank > registers[register]) registers[register] = rank
        }

        fun distinctSources(): Double {
            var sum = 0.0
            var zeros = 0
            for (r in registers) {
                sum += 1.0 / (1L shl r.toInt())
                if (r.toInt() == 0) zeros++
            }
            val m = HLL_REGISTERS.toDouble()
            val estimate = 0.7182 * m * m / sum
            return if (estimate <= 2.5 * m && zeros > 0) m * kotlin.math.ln(m / zeros) else estimate
        }
    }

    private val targetSketches = object : LinkedHashMap<String, TargetSketch>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, TargetSketch>?) = size > MAX_FLOOD_TARGETS
    }

    private fun detectDistributedFlood(sourceIp: String, destIp: String, protocol: String, flags: String) {
        // Replies carry ACK, so a busy server answering many clients does not count against them
        if (protocol == "TCP" && flags.contains("ACK")) return
        if (protocol != "TCP" && protocol != "UDP" && protocol != "ICMP") return
        val now = PacketClock.now()
        val sketch = targetSketches.getOrPut(destIp) { TargetSketch() }
        if (now - sketch.windowStart > 1000) sketch.clear(now)
        sketch.packets++
        sketch.add(sourceIp)
        if (sketch.packets >= DISTRIBUTED_FLOOD_PACKETS && sketch.distinctSources() >= sketch.packets * DISTRIBUTED_SOURCE_SHARE) {
            reportAnomaly(
                Anomaly(
                    AnomalyType.DISTRIBUTED_FLOOD, Severity.CRITICAL,
                    "Flood at one target from about ${sketch.distinctSources().toInt()} sources: spoofed or distributed",
                    destinationIp = destIp
                )
            )
            sketch.clear(now)
        }
    }

    private fun checkHighEntropyPayload(
        payload: ByteArray,
        protocol: String,
        appName: String?,
        outgoing: Boolean,
        sourceIp: String,
        destinationIp: String
    ) {
        if (payload.size < MIN_PAYLOAD_SIZE_FOR_ENTROPY) return
        if (protocol.isEmpty()) return
        // COMMIT 4: skip known compressed/encrypted binary formats
        if (isKnownCompressedFormat(payload)) return
        // COMMIT 1: skip protocols that legitimately always produce high entropy. The record's
        // protocol field holds the transport (TCP/UDP), so the application name is what to test.
        if (appName != null && ENTROPY_ALLOWLIST.any { it.equals(appName, ignoreCase = true) }) return

        // High entropy only means something where cleartext is expected. A download is usually
        // compressed, so HTTP is judged on the upload side, and an unknown port proves nothing:
        // most mobile apps speak their own encrypted protocol on one.
        val cleartextExpected = (appName == "HTTP" || appName == "DNS") && outgoing
        if (protocol != "ICMP" && !cleartextExpected) return

        val entropy = calculateEntropy(payload)

        // Determine whether this packet's entropy would qualify for any alert
        val wouldAlert = when {
            protocol == "ICMP" && entropy > 6.0 -> true
            cleartextExpected && entropy > ENTROPY_THRESHOLD_SUSPICIOUS -> true
            else -> false
        }

        // COMMIT 3: require 5 consecutive high-entropy packets before alerting;
        // a single outlier packet is not evidence of tunneling
        if (wouldAlert) {
            highEntropyPacketCount[sourceIp] = (highEntropyPacketCount[sourceIp] ?: 0) + 1
            if ((highEntropyPacketCount[sourceIp] ?: 0) < ENTROPY_CONSECUTIVE_THRESHOLD) return
        } else {
            highEntropyPacketCount[sourceIp] = 0
            return
        }

        // COMMIT 2: cooldown — same source suppressed for 30 s after an alert
        val now = PacketClock.now()
        val lastAlert = entropyAlertCooldown[sourceIp] ?: 0L
        if (now - lastAlert < ENTROPY_COOLDOWN_MS) return
        entropyAlertCooldown[sourceIp] = now

        when {
            protocol == "ICMP" && entropy > 6.0 -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.COVERT_CHANNEL,
                    severity = Severity.CRITICAL,
                    description = "ICMP payload entropy ${"%.2f".format(entropy)} — possible icmptunnel/ptunnel covert channel",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
            cleartextExpected && entropy > ENTROPY_THRESHOLD_HIGH -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.HIGH_ENTROPY_PAYLOAD,
                    severity = Severity.HIGH,
                    description = "High entropy ${"%.2f".format(entropy)} in $appName payload — possible exfiltration",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
            cleartextExpected && entropy > ENTROPY_THRESHOLD_SUSPICIOUS -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.HIGH_ENTROPY_PAYLOAD,
                    severity = Severity.MEDIUM,
                    description = "Suspicious entropy ${"%.2f".format(entropy)} in $appName payload",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
        }
    }

    private fun checkDnsTunneling(payload: ByteArray, appName: String?, sourceIp: String, destinationIp: String) {
        if (appName != "DNS") return
        if (payload.size < MIN_PAYLOAD_SIZE_FOR_ENTROPY) return
        val entropy = calculateEntropy(payload)

        // COMMIT 3: require 3 consecutive high-entropy DNS packets; real tunneling is a stream
        if (entropy > ENTROPY_THRESHOLD_DNS_TUNNEL) {
            dnsHighEntropyCount[sourceIp] = (dnsHighEntropyCount[sourceIp] ?: 0) + 1
            if ((dnsHighEntropyCount[sourceIp] ?: 0) < DNS_ENTROPY_CONSECUTIVE_THRESHOLD) return
        } else {
            dnsHighEntropyCount[sourceIp] = 0
            return
        }

        // COMMIT 2: cooldown check
        val now = PacketClock.now()
        val lastAlert = entropyAlertCooldown[sourceIp] ?: 0L
        if (now - lastAlert < ENTROPY_COOLDOWN_MS) return
        entropyAlertCooldown[sourceIp] = now

        reportAnomaly(
            Anomaly(
                type = AnomalyType.DNS_TUNNELING,
                severity = Severity.HIGH,
                description = "DNS query entropy ${"%.2f".format(entropy)} suggests tunneling tool (dnscat2/iodine)",
                sourceIp = sourceIp,
                destinationIp = destinationIp
            )
        )
    }

    // COMMIT 4: magic-byte pre-filter — skip known compressed/media formats before
    // computing entropy, as these legitimately produce high entropy values
    internal fun isKnownCompressedFormat(payload: ByteArray): Boolean {
        if (payload.size < 4) return false
        val b = payload
        return when {
            b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() -> true  // JPEG
            b[0] == 0x89.toByte() && b[1] == 0x50.toByte() -> true  // PNG
            b[0] == 0x47.toByte() && b[1] == 0x49.toByte() -> true  // GIF
            b[0] == 0x50.toByte() && b[1] == 0x4B.toByte() -> true  // ZIP/APK/JAR
            b[0] == 0x1F.toByte() && b[1] == 0x8B.toByte() -> true  // GZIP
            b[0] == 0x42.toByte() && b[1] == 0x5A.toByte() -> true  // BZIP2
            b[0] == 0xFD.toByte() && b[1] == 0x37.toByte() -> true  // XZ
            b[0] == 0x52.toByte() && b[1] == 0x61.toByte() -> true  // RAR
            b[0] == 0x37.toByte() && b[1] == 0x7A.toByte() -> true  // 7ZIP
            b[0] == 0x00.toByte() && b[1] == 0x00.toByte()
                && b[2] == 0x00.toByte() -> true                     // MP4/MOV
            b[0] == 0x1A.toByte() && b[1] == 0x45.toByte() -> true  // WebM/MKV
            else -> false
        }
    }

    // CDNs and ad networks put hashes in their names, so one long name means nothing. A tunnel needs
    // many of them under one zone to carry anything at all.
    private fun detectDnsTunneling(queryName: String, sourceIp: String, destinationIp: String) {
        if (queryName.length <= DNS_LONG_NAME) return
        val now = PacketClock.now()
        val zone = queryName.trimEnd('.').split('.').takeLast(2).joinToString(".")
        val burst = longNames.getOrPut(zone) { longArrayOf(now, 0L) }
        if (now - burst[0] > DNS_ZONE_WINDOW_MS) {
            burst[0] = now
            burst[1] = 0L
        }
        burst[1]++
        if (burst[1] >= DNS_ZONE_LONG_NAMES) {
            reportAnomaly(
                Anomaly(AnomalyType.DNS_TUNNELING, Severity.MEDIUM, "Many long DNS names under $zone: possible tunnel", sourceIp, destinationIp)
            )
        }
    }

    /**
     * SYN+FIN and SYN+RST are illegal TCP flag combinations under RFC 9293 —
     * no legitimate stack ever sets them together. Crafted packets with these
     * combinations are a long-standing firewall/IDS evasion and stack-fingerprinting
     * technique (e.g. "SYN/FIN scanning"). This was previously unreachable: the
     * "flags" field it depends on was never populated on the VPN-mode capture
     * path (see ZdtunVpnService.extractTcpFlags), only on rooted libpcap mode.
     */
    private fun detectMalformedTcpFlags(sourceIp: String, destIp: String, flags: String) {
        val hasSyn = flags.contains("SYN")
        val hasFin = flags.contains("FIN")
        val hasRst = flags.contains("RST")
        if (!hasSyn || (!hasFin && !hasRst)) return

        val now = PacketClock.now()
        val cooldownKey = "malformed:$sourceIp"
        val lastAlert = entropyAlertCooldown[cooldownKey] ?: 0L
        if (now - lastAlert < ENTROPY_COOLDOWN_MS) return
        entropyAlertCooldown[cooldownKey] = now

        reportAnomaly(
            Anomaly(
                AnomalyType.MALFORMED_PACKET,
                Severity.MEDIUM,
                "Malformed TCP packet: illegal flag combination (${flags.trim()})",
                sourceIp = sourceIp,
                destinationIp = destIp,
                details = mapOf("flags" to flags.trim())
            )
        )
    }

    private fun detectArpSpoofing(packetInfo: Map<String, Any>) {
        val senderIp = packetInfo["senderIp"] as? String ?: return
        val senderMac = packetInfo["senderMac"] as? String ?: return
        // An address probe claims nothing: any number of machines may send them
        if (senderIp == "0.0.0.0") return
        val cached = arpCache[senderIp]
        if (cached != null && cached != senderMac) {
            reportAnomaly(
                Anomaly(AnomalyType.ARP_SPOOFING, Severity.CRITICAL, "ARP spoofing from $senderIp", senderIp)
            )
        }
        arpCache[senderIp] = senderMac

        // A capture that starts after the poisoning never sees a binding change, but the poisoner's
        // MAC still claims two addresses: its own and the one it is impersonating. A machine falling
        // back to a link-local address before DHCP answers is doing nothing of the kind.
        if (senderIp.startsWith("169.254.")) return
        val now = PacketClock.now()
        val claims = macClaims.getOrPut(senderMac) { ConcurrentHashMap() }
        claims[senderIp] = now
        claims.entries.removeIf { now - it.value > ARP_MAC_WINDOW_MS }
        if (claims.size >= 2) {
            reportAnomaly(
                Anomaly(
                    AnomalyType.ARP_SPOOFING, Severity.CRITICAL,
                    "One MAC claims ${claims.size} addresses: possible ARP poisoning", senderIp
                )
            )
        }
    }

    // === COMMIT 8: Rate extraction — feed the adaptive threshold manager ===

    private fun getCurrentDnsRate(): Int = dnsQueryTracker.queries

    // No per-window ARP rate counter exists; return 0 so the adaptive manager
    // keeps the floor value for ARP thresholds
    private fun getCurrentArpRate(): Int = 0

    // === COMMIT 2: Entropy cooldown maintenance ===
    private fun clearStaleEntropyCooldowns() {
        val cutoff = PacketClock.now() - 300_000L
        entropyAlertCooldown.entries.removeIf { it.value < cutoff }
    }

    // === Utility ===
    private fun reportAnomaly(anomaly: Anomaly) {
        if (adaptiveThresholds.isInLearningPeriod()) return

        val finding = anomaly.description.takeIf { it.startsWith("[") }?.substringBefore(']') ?: anomaly.type.name
        val host = currentApp.ifEmpty { anomaly.sourceIp ?: anomaly.destinationIp ?: "" }
        val key = "$finding|$host"
        val now = PacketClock.now()
        val last = alertSuppression[key]
        if (last != null && now - last < ALERT_SUPPRESS_MS) return
        alertSuppression[key] = now
        if (alertSuppression.size > 4096) alertSuppression.entries.removeIf { now - it.value > ALERT_SUPPRESS_MS }

        val named = if (currentApp.isEmpty()) anomaly else anomaly.copy(
            description = "${anomaly.description} (app: $currentApp)",
            details = anomaly.details + ("app" to currentApp)
        )
        for (listener in anomalyListeners) listener(named)
    }

    /** Skipped packets went unanalysed, and an attacker could cause that on purpose, so say so. */
    fun reportAnalysisOverload(skippedPackets: Long) {
        // This is about the analyser and not about whichever app happened to be last in the queue
        currentApp = ""
        reportAnomaly(
            Anomaly(
                AnomalyType.ANALYSIS_OVERLOAD, Severity.MEDIUM,
                "Analysis skipped $skippedPackets packets under load",
                details = mapOf("skippedPackets" to skippedPackets)
            )
        )
    }

    // === Stubs for future ML-based detection ===
    private fun detectBehavioralAnomalies(packetInfo: Map<String, Any>) {}
    private fun detectConnectionPatternAnomalies(packetInfo: Map<String, Any>) {}
    private fun updateTrafficStatistics(packetInfo: Map<String, Any>, payload: ByteArray?) {}
    private fun updateBehavioralModels(packetInfo: Map<String, Any>) {}
    private fun updateAdaptiveThresholds() {}

    // === Stats and Maintenance ===
    fun reset() {
        FlowTable.reset()
        FlowDetectors.reset()
        targetSketches.clear()
        macClaims.clear()
        longNames.clear()
        currentApp = ""
        portScans.clear()
        synFloodTracker.clear()
        connectionTracker.clear()
        arpCache.clear()
        dnsQueryTracker.domains.clear()
        highEntropyPacketCount.clear()
        dnsHighEntropyCount.clear()
        entropyAlertCooldown.clear()
        alertSuppression.clear()
        peakPorts.set(0)
        peakSyn.set(0)
        peakConnections.set(0)
        lastAdaptiveSample = 0L
        packetCount.set(0)
    }

    fun getStatistics(): Map<String, Any> = mapOf(
        "activePortScans" to portScans.size,
        "activeSynFloods" to synFloodTracker.size,
        "activeConnections" to connectionTracker.size
    )

    // === Cleanup ===
    fun cleanup() {
        val now = PacketClock.now()
        portScans.entries.removeAll { now - it.value.lastSeen > 20000 }
        synFloodTracker.entries.removeAll { now - it.value.windowStart > 10000 }
        connectionTracker.entries.removeAll { now - it.value.windowStart > 10000 }
        clearStaleEntropyCooldowns()

        // A spoofed ARP storm could otherwise fill these with made-up addresses
        if (arpCache.size > MAX_ARP_ENTRIES) arpCache.clear()
        if (macClaims.size > MAX_ARP_ENTRIES) macClaims.clear()

        // highEntropyPacketCount/dnsHighEntropyCount have no per-entry timestamp
        // (they're plain consecutive-hit counters keyed by source IP), so unlike
        // the trackers above they can't be pruned by age — only bounded by size.
        // Every long-running capture session accumulates one entry per unique
        // source IP that ever produced high-entropy traffic, forever, otherwise.
        if (highEntropyPacketCount.size > 500) highEntropyPacketCount.clear()
        if (dnsHighEntropyCount.size > 500) dnsHighEntropyCount.clear()
    }
}
