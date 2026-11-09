package com.example.packet_analyzer

/**
 * Adaptive Threshold Manager
 *
 * Learns normal traffic rates during a 60-second baseline period, then sets
 * detection thresholds proportional to that baseline.  Hard floor values
 * keep quiet networks sensitive. Ceilings are fixed when learning ends, and a sample
 * at or above the current threshold never trains the baseline, so an attack cannot
 * raise the threshold it is being measured against.
 */
class AdaptiveThresholdManager {

    companion object {
        const val LEARNING_PERIOD_MS = 60_000L  // 60-second learning window
        const val ALPHA_SLOW = 0.05             // slow EMA for stable networks
        const val ALPHA_FAST = 0.15             // fast EMA for volatile networks

        // Absolute floor values — thresholds can never fall below these,
        // regardless of how quiet the observed baseline is
        const val FLOOR_PORT_SCAN = 8
        const val FLOOR_SYN_FLOOD = 50
        // Browsing on a real phone peaks at 45 new connections a second during page loads
        const val FLOOR_CONNECTION_RATE = 100
        const val FLOOR_DNS_QUERY_RATE = 10
        const val FLOOR_ARP_RATE = 3

        // Threshold ceiling = learned baseline * CEILING_MULTIPLIER, never below the default
        const val CEILING_MULTIPLIER = 4.0

        const val DEFAULT_PORT_SCAN = 20
        const val DEFAULT_SYN_FLOOD = 100
        const val DEFAULT_CONNECTION_RATE = 100
        const val DEFAULT_DNS_QUERY_RATE = 30
        const val DEFAULT_ARP_RATE = 10
    }

    // Current adaptive threshold values exposed to AnomalyDetector
    var portScanThreshold: Int = DEFAULT_PORT_SCAN
        private set
    var synFloodThreshold: Int = DEFAULT_SYN_FLOOD
        private set
    var connectionRateThreshold: Int = DEFAULT_CONNECTION_RATE
        private set
    var dnsQueryRateThreshold: Int = DEFAULT_DNS_QUERY_RATE
        private set
    var arpRateThreshold: Int = DEFAULT_ARP_RATE
        private set

    // Learning period state
    private var learningStartTime: Long = 0L
    private var isLearning: Boolean = false
    private var learningComplete: Boolean = false

    // Observations collected during the learning window
    private val observedPortScansPerWindow = mutableListOf<Int>()
    private val observedSynRates = mutableListOf<Int>()
    private val observedConnectionRates = mutableListOf<Int>()
    private val observedDnsRates = mutableListOf<Int>()
    private val observedArpRates = mutableListOf<Int>()

    // EMA baseline values updated continuously after learning completes
    private var baselinePortScan = 0.0
    private var baselineSynFlood = 0.0
    private var baselineConnectionRate = 0.0
    private var baselineDnsRate = 0.0
    private var baselineArpRate = 0.0

    // Fixed when learning ends; the EMA can move a threshold only up to here
    private var ceilingPortScan = DEFAULT_PORT_SCAN
    private var ceilingSynFlood = DEFAULT_SYN_FLOOD
    private var ceilingConnectionRate = DEFAULT_CONNECTION_RATE
    private var ceilingDnsRate = DEFAULT_DNS_QUERY_RATE
    private var ceilingArpRate = DEFAULT_ARP_RATE

    fun startLearning() {
        learningStartTime = PacketClock.now()
        isLearning = true
        learningComplete = false
        observedPortScansPerWindow.clear()
        observedSynRates.clear()
        observedConnectionRates.clear()
        observedDnsRates.clear()
        observedArpRates.clear()
    }

    fun isInLearningPeriod(): Boolean {
        if (!isLearning) return false
        return PacketClock.now() - learningStartTime < LEARNING_PERIOD_MS
    }

    fun recordObservation(
        portScans: Int,
        synRate: Int,
        connectionRate: Int,
        dnsRate: Int,
        arpRate: Int
    ) {
        when {
            isInLearningPeriod() -> {
                observedPortScansPerWindow.add(portScans)
                observedSynRates.add(synRate)
                observedConnectionRates.add(connectionRate)
                observedDnsRates.add(dnsRate)
                observedArpRates.add(arpRate)
            }
            isLearning && !learningComplete -> finalizeLearning()
            learningComplete -> updateEMA(portScans, synRate, connectionRate, dnsRate, arpRate)
        }
    }

    private fun finalizeLearning() {
        isLearning = false
        learningComplete = true

        // 90th-percentile baseline avoids skewing from isolated spikes during learning
        baselinePortScan = percentile90(observedPortScansPerWindow)
        baselineSynFlood = percentile90(observedSynRates)
        baselineConnectionRate = percentile90(observedConnectionRates)
        baselineDnsRate = percentile90(observedDnsRates)
        baselineArpRate = percentile90(observedArpRates)

        ceilingPortScan = ceilingFor(baselinePortScan, DEFAULT_PORT_SCAN)
        ceilingSynFlood = ceilingFor(baselineSynFlood, DEFAULT_SYN_FLOOD)
        ceilingConnectionRate = ceilingFor(baselineConnectionRate, DEFAULT_CONNECTION_RATE)
        ceilingDnsRate = ceilingFor(baselineDnsRate, DEFAULT_DNS_QUERY_RATE)
        ceilingArpRate = ceilingFor(baselineArpRate, DEFAULT_ARP_RATE)

        recalculateThresholds()
    }

    private fun ceilingFor(baseline: Double, default: Int): Int =
        (baseline * CEILING_MULTIPLIER).toInt().coerceAtLeast(default)

    private fun updateEMA(
        portScans: Int,
        synRate: Int,
        connectionRate: Int,
        dnsRate: Int,
        arpRate: Int
    ) {
        // A sample that reached the threshold is a detection, and must not teach the baseline
        if (portScans < portScanThreshold) {
            baselinePortScan = ALPHA_SLOW * portScans + (1 - ALPHA_SLOW) * baselinePortScan
        }
        if (synRate < synFloodThreshold) {
            baselineSynFlood = ALPHA_SLOW * synRate + (1 - ALPHA_SLOW) * baselineSynFlood
        }
        if (connectionRate < connectionRateThreshold) {
            baselineConnectionRate = ALPHA_SLOW * connectionRate + (1 - ALPHA_SLOW) * baselineConnectionRate
        }
        if (dnsRate < dnsQueryRateThreshold) {
            baselineDnsRate = ALPHA_SLOW * dnsRate + (1 - ALPHA_SLOW) * baselineDnsRate
        }
        if (arpRate < arpRateThreshold) {
            baselineArpRate = ALPHA_SLOW * arpRate + (1 - ALPHA_SLOW) * baselineArpRate
        }

        recalculateThresholds()
    }

    private fun recalculateThresholds() {
        portScanThreshold = clamp((baselinePortScan * 2.5).toInt(), FLOOR_PORT_SCAN, ceilingPortScan)
        synFloodThreshold = clamp((baselineSynFlood * 2.5).toInt(), FLOOR_SYN_FLOOD, ceilingSynFlood)
        connectionRateThreshold = clamp((baselineConnectionRate * 2.5).toInt(), FLOOR_CONNECTION_RATE, ceilingConnectionRate)
        dnsQueryRateThreshold = clamp((baselineDnsRate * 2.5).toInt(), FLOOR_DNS_QUERY_RATE, ceilingDnsRate)
        arpRateThreshold = clamp((baselineArpRate * 2.5).toInt(), FLOOR_ARP_RATE, ceilingArpRate)
    }

    internal fun percentile90(values: List<Int>): Double {
        if (values.isEmpty()) return 0.0
        val sorted = values.sorted()
        val index = (sorted.size * 0.90).toInt().coerceAtMost(sorted.size - 1)
        return sorted[index].toDouble()
    }

    private fun clamp(value: Int, min: Int, max: Int): Int = value.coerceIn(min, max)

    fun getStatus(): Map<String, Any> {
        return mapOf(
            "isLearning" to isInLearningPeriod(),
            "learningComplete" to learningComplete,
            "thresholds" to mapOf(
                "portScan" to portScanThreshold,
                "synFlood" to synFloodThreshold,
                "connectionRate" to connectionRateThreshold,
                "dnsQueryRate" to dnsQueryRateThreshold,
                "arpRate" to arpRateThreshold
            ),
            "baselines" to mapOf(
                "portScan" to baselinePortScan,
                "synFlood" to baselineSynFlood,
                "connectionRate" to baselineConnectionRate,
                "dnsRate" to baselineDnsRate,
                "arpRate" to baselineArpRate
            )
        )
    }

    fun reset() {
        portScanThreshold = DEFAULT_PORT_SCAN
        synFloodThreshold = DEFAULT_SYN_FLOOD
        connectionRateThreshold = DEFAULT_CONNECTION_RATE
        dnsQueryRateThreshold = DEFAULT_DNS_QUERY_RATE
        arpRateThreshold = DEFAULT_ARP_RATE
        ceilingPortScan = DEFAULT_PORT_SCAN
        ceilingSynFlood = DEFAULT_SYN_FLOOD
        ceilingConnectionRate = DEFAULT_CONNECTION_RATE
        ceilingDnsRate = DEFAULT_DNS_QUERY_RATE
        ceilingArpRate = DEFAULT_ARP_RATE
        baselinePortScan = 0.0
        baselineSynFlood = 0.0
        baselineConnectionRate = 0.0
        baselineDnsRate = 0.0
        baselineArpRate = 0.0
        isLearning = false
        learningComplete = false
    }
}
