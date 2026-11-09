package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Rule-Based Detection Engine
 * Evaluates complex rules combining multiple conditions and temporal logic
 */
object RuleEngine {
    private const val TAG = "RuleEngine"

    // Rule data structures
    data class Rule(
        val id: String,
        val name: String,
        val description: String,
        val severity: AnomalyDetector.Severity,
        val category: String,
        val conditions: List<Condition>,
        val action: Action,
        val enabled: Boolean = true
    )

    sealed class Condition {
        // Basic conditions
        data class ProtocolEquals(val protocol: String) : Condition()
        data class PortEquals(val port: Int, val direction: Direction = Direction.DESTINATION) : Condition()
        data class PortInRange(val start: Int, val end: Int, val direction: Direction = Direction.DESTINATION) : Condition()
        data class IpEquals(val ip: String, val direction: Direction = Direction.DESTINATION) : Condition()
        data class IpInCidr(val cidr: String, val direction: Direction = Direction.DESTINATION) : Condition()
        data class FlagsContain(val flags: List<String>) : Condition()
        data class DirectionEquals(val direction: String) : Condition()

        // Payload conditions
        data class PayloadSize(val operator: Operator, val size: Int) : Condition()
        data class PayloadContains(val pattern: String) : Condition()
        data class PayloadMatches(val regex: Regex) : Condition()

        // Header conditions
        data class HeaderExists(val header: String) : Condition()
        data class HeaderEquals(val header: String, val value: String) : Condition()
        data class HeaderMatches(val header: String, val regex: Regex) : Condition()

        // Rate/Temporal conditions
        data class PacketRate(val operator: Operator, val count: Int, val windowMs: Long) : Condition()
        data class ByteRate(val operator: Operator, val bytes: Long, val windowMs: Long) : Condition()
        data class UniqueDestinations(val operator: Operator, val count: Int, val windowMs: Long) : Condition()
        data class TimeSince(val event: String, val operator: Operator, val durationMs: Long) : Condition()

        // Logical combinations
        data class And(val conditions: List<Condition>) : Condition()
        data class Or(val conditions: List<Condition>) : Condition()
        data class Not(val condition: Condition) : Condition()

        // Domain conditions
        data class DomainEquals(val domain: String) : Condition()
        data class DomainContains(val substring: String) : Condition()
        data class DomainMatches(val regex: Regex) : Condition()

        // DNS conditions
        data class DnsQueryType(val type: String) : Condition()
        data class DnsResponseCount(val operator: Operator, val count: Int) : Condition()

        // HTTP conditions
        data class HttpMethod(val method: String) : Condition()
        data class HttpStatus(val operator: Operator, val status: Int) : Condition()
        data class UrlContains(val substring: String) : Condition()
        data class UrlMatches(val regex: Regex) : Condition()
    }

    enum class Direction { SOURCE, DESTINATION, BOTH }
    enum class Operator { EQUALS, NOT_EQUALS, GREATER_THAN, LESS_THAN, GREATER_EQUAL, LESS_EQUAL }

    sealed class Action {
        object Alert : Action()
        data class AlertWithDetails(val message: String) : Action()
        object Block : Action()  // For future implementation
        object Log : Action()
        data class Custom(val handler: (Map<String, Any>) -> Unit) : Action()
    }

    // Rule state tracking
    private val rules = mutableListOf<Rule>()
    private val ruleState = ConcurrentHashMap<String, RuleState>()

    /**
     * Recent packets from one source that already satisfied a rule's stateless conditions.
     * Rate predicates count these and nothing else, so "more than 10 per second" means ten
     * packets of the suspicious kind from this source, not ten packets of any kind from anyone.
     */
    class SourceWindow {
        private val times = ArrayDeque<Long>()
        private val destinations = ArrayDeque<String>()
        private val sizes = ArrayDeque<Int>()

        fun add(now: Long, destination: String, size: Int) {
            times.addLast(now)
            destinations.addLast(destination)
            sizes.addLast(size)
            if (times.size > MAX_WINDOW_ENTRIES) {
                times.removeFirst()
                destinations.removeFirst()
                sizes.removeFirst()
            }
        }

        fun bytesSince(start: Long, destination: String): Long {
            var total = 0L
            val t = times.asReversed().iterator()
            val s = sizes.asReversed().iterator()
            val d = destinations.asReversed().iterator()
            while (t.hasNext() && t.next() >= start) {
                val size = s.next()
                if (d.next() == destination) total += size
            }
            return total
        }

        fun countSince(start: Long): Int {
            var n = 0
            val it = times.asReversed().iterator()
            while (it.hasNext() && it.next() >= start) n++
            return n
        }

        fun uniqueDestinationsSince(start: Long): Int {
            val seen = HashSet<String>()
            val t = times.asReversed().iterator()
            val d = destinations.asReversed().iterator()
            while (t.hasNext() && t.next() >= start) seen.add(d.next())
            return seen.size
        }
    }

    private const val MAX_WINDOW_ENTRIES = 1000
    private const val MAX_SOURCES_PER_RULE = 64
    private const val BULK_UPLOAD_BYTES = 1024L * 1024

    data class RuleState(
        var lastTriggered: Long = 0,
        var triggerCount: Int = 0,
        val windows: LinkedHashMap<String, SourceWindow> =
            object : LinkedHashMap<String, SourceWindow>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, SourceWindow>?) =
                    size > MAX_SOURCES_PER_RULE
            }
    )

    private val SQLI_PATTERN = Regex(
        "union(\\s+all)?\\s+select|'\\s*or\\s*'?\\d*'?\\s*=|\\bor\\s+\\d+\\s*=\\s*\\d+|" +
            "'\\s*(--|#)|;\\s*(drop|delete|insert|update)\\s|\\b(sleep|benchmark)\\s*\\(|" +
            "waitfor\\s+delay|information_schema|xp_cmdshell",
        RegexOption.IGNORE_CASE
    )

    init {
        loadDefaultRules()
    }

    private fun loadDefaultRules() {
        // Rule 1: Port Scan Detection (Advanced)
        rules.add(
            Rule(
                id = "RULE-001",
                name = "Advanced Port Scan",
                description = "Detects port scanning with multiple unique destinations",
                severity = AnomalyDetector.Severity.HIGH,
                category = "RECONNAISSANCE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            // A probe opens or pokes at a connection: SYN, FIN, NULL and Xmas scans
                            // all leave ACK clear, while every packet of an open flow sets it
                            Condition.Not(Condition.FlagsContain(listOf("ACK"))),
                            // Browsing on a real phone reaches 80 distinct hosts in 10 s, so a
                            // lower limit calls every page load a sweep
                            Condition.UniqueDestinations(Operator.GREATER_THAN, 100, 10000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Port scan detected with advanced patterns")
            )
        )

        // Rule 2: SQL Injection Attack
        rules.add(
            Rule(
                id = "RULE-002",
                name = "SQL Injection Attack",
                description = "Detects SQL injection attempts in HTTP traffic",
                severity = AnomalyDetector.Severity.CRITICAL,
                category = "WEB_ATTACK",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            Condition.HeaderEquals("type", "request"),
                            Condition.Or(
                                listOf(
                                    Condition.UrlMatches(SQLI_PATTERN),
                                    Condition.PayloadMatches(SQLI_PATTERN)
                                )
                            )
                        )
                    )
                ),
                action = Action.AlertWithDetails("SQL injection attack detected")
            )
        )

        // Rule 3: Suspicious File Download
        rules.add(
            Rule(
                id = "RULE-003",
                name = "Malicious File Download",
                description = "Detects download of potentially malicious file types",
                severity = AnomalyDetector.Severity.HIGH,
                category = "MALWARE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.HttpMethod("GET"),
                            Condition.UrlMatches(Regex("\\.(exe|scr|bat|cmd|vbs|ps1|dll|jar|apk)(\\?.*)?$", RegexOption.IGNORE_CASE))
                        )
                    )
                ),
                action = Action.AlertWithDetails("Suspicious file download attempt")
            )
        )

        // Rule 4: DNS Tunneling
        rules.add(
            Rule(
                id = "RULE-004",
                name = "DNS Tunneling",
                description = "Detects data exfiltration via DNS queries",
                severity = AnomalyDetector.Severity.HIGH,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("UDP"),
                            Condition.PortEquals(53, Direction.DESTINATION),
                            Condition.Or(
                                listOf(
                                    Condition.PayloadSize(Operator.GREATER_THAN, 128),
                                    // A single label this long is encoded data, hex or base32 alike
                                    Condition.DomainMatches(Regex("(^|\\.)[0-9a-zA-Z]{32,}(\\.|$)"))
                                )
                            ),
                            Condition.PacketRate(Operator.GREATER_THAN, 10, 1000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Possible DNS tunneling detected")
            )
        )

        // Rule 5: Brute Force Attack
        rules.add(
            Rule(
                id = "RULE-005",
                name = "Brute Force Attack",
                description = "Detects brute force authentication attempts",
                severity = AnomalyDetector.Severity.HIGH,
                category = "BRUTE_FORCE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.Or(
                                listOf(
                                    Condition.PortEquals(22),  // SSH
                                    Condition.PortEquals(3389), // RDP
                                    Condition.PortEquals(21),  // FTP
                                    Condition.PortEquals(23)   // Telnet
                                )
                            ),
                            // Counts connection attempts: one login session is many packets
                            Condition.FlagsContain(listOf("SYN")),
                            Condition.Not(Condition.FlagsContain(listOf("ACK"))),
                            Condition.PacketRate(Operator.GREATER_THAN, 7, 60000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Brute force attack detected")
            )
        )

        // Rule 6: Cryptomining Activity
        rules.add(
            Rule(
                id = "RULE-006",
                name = "Cryptomining Detection",
                description = "Detects cryptocurrency mining pool connections",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "MALWARE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            // The stratum wire format never says "stratum"; it says these.
                            // Pools listen on any port, so the port is no use as a filter.
                            Condition.PayloadMatches(
                                Regex("mining\\.(subscribe|authorize|submit)|\"method\"\\s*:\\s*\"login\".*\"(agent|algo)\"|stratum\\+(tcp|ssl)://")
                            )
                        )
                    )
                ),
                action = Action.AlertWithDetails("Cryptomining pool connection detected")
            )
        )

        // Rule 7: Suspicious Outbound Traffic
        rules.add(
            Rule(
                id = "RULE-007",
                name = "Suspicious Outbound Traffic",
                description = "Large amount of outbound data to single destination",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.DirectionEquals("outgoing"),
                            Condition.PayloadSize(Operator.GREATER_THAN, 1024),
                            // Bytes, since the tunnel MTU decides how many packets a megabyte takes, and to
                            // one destination: a page load's many large TLS hellos are no upload
                            Condition.ByteRate(Operator.GREATER_THAN, BULK_UPLOAD_BYTES, 10000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Unusual outbound traffic volume")
            )
        )

        // Rule 8: Shellcode Execution
        rules.add(
            Rule(
                id = "RULE-008",
                name = "Shellcode Pattern",
                description = "Detects common shellcode patterns",
                severity = AnomalyDetector.Severity.CRITICAL,
                category = "EXPLOIT",
                conditions = listOf(
                    Condition.Or(
                        listOf(
                            Condition.PayloadMatches(Regex("\\x90{16,}")), // NOP sled
                            // xor eax,eax; push eax; push imm32. Written as code points, since the
                            // payload is matched as ISO-8859-1 text. A two-byte pattern such as
                            // EB 0E would match ciphertext by chance in about 2% of full-size packets.
                            Condition.PayloadContains("\u0031\u00c0\u0050\u0068")
                        )
                    )
                ),
                action = Action.AlertWithDetails("Shellcode pattern detected")
            )
        )

        // Rule 9: Suspicious User-Agent
        rules.add(
            Rule(
                id = "RULE-009",
                name = "Suspicious User-Agent",
                description = "Detects suspicious or automated user agents",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "RECONNAISSANCE",
                conditions = listOf(
                    Condition.Or(
                        listOf(
                            Condition.HeaderMatches("User-Agent", Regex("[Bb]ot")),
                            Condition.HeaderMatches("User-Agent", Regex("[Ss]canner")),
                            Condition.HeaderMatches("User-Agent", Regex("[Cc]rawler")),
                            Condition.HeaderMatches("User-Agent", Regex("python|nikto|nmap|sqlmap", RegexOption.IGNORE_CASE)),
                            Condition.HeaderMatches("User-Agent", Regex("curl", RegexOption.IGNORE_CASE))
                        )
                    )
                ),
                action = Action.AlertWithDetails("Suspicious User-Agent detected")
            )
        )

        // Rule 10: ICMP Tunnel
        rules.add(
            Rule(
                id = "RULE-010",
                name = "ICMP Tunneling",
                description = "Detects data tunneling via ICMP",
                severity = AnomalyDetector.Severity.HIGH,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("ICMP"),
                            Condition.PayloadSize(Operator.GREATER_THAN, 64),
                            Condition.PacketRate(Operator.GREATER_THAN, 10, 1000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("ICMP tunneling detected")
            )
        )

    }

    /**
     * Evaluate all rules against a packet
     */
    fun evaluateRules(packetInfo: Map<String, Any>, payload: ByteArray?): List<RuleMatch> {
        val matches = mutableListOf<RuleMatch>()
        // Decode once per packet, not once per rule/condition — up to 10
        // rules each with their own PayloadContains/PayloadMatches
        // conditions used to independently re-decode the same bytes.
        val payloadStr = payload?.let { String(it, Charsets.ISO_8859_1) }

        for (rule in rules) {
            if (!rule.enabled) continue

            try {
                val state = ruleState.getOrPut(rule.id) { RuleState() }

                // First pass ignores the rate predicates: a packet that fails here is not the
                // kind this rule counts, so it never enters the rule's window.
                if (!evaluateConditions(rule.conditions, packetInfo, payload, payloadStr, null)) continue

                val hasTemporal = rule.conditions.any(::isTemporal)
                var window: SourceWindow? = null
                if (hasTemporal) {
                    window = state.windows.getOrPut(AppContext.principal(packetInfo)) { SourceWindow() }
                    window.add(PacketClock.now(), packetInfo["destinationIp"]?.toString() ?: "", (packetInfo["payloadSize"] as? Int) ?: payload?.size ?: 0)
                }

                // Evaluate conditions
                if (!hasTemporal || evaluateConditions(rule.conditions, packetInfo, payload, payloadStr, window)) {
                    state.lastTriggered = PacketClock.now()
                    state.triggerCount++

                    matches.add(
                        RuleMatch(
                            rule = rule,
                            timestamp = PacketClock.now(),
                            details = buildMatchDetails(rule, packetInfo)
                        )
                    )

                    // Execute action
                    executeAction(rule.action, packetInfo)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error evaluating rule ${rule.id}: ${e.message}")
            }
        }

        return matches
    }

    /** True when the condition tree holds a predicate that needs the rule's source window. */
    private fun isTemporal(condition: Condition): Boolean = when (condition) {
        is Condition.PacketRate, is Condition.ByteRate, is Condition.UniqueDestinations -> true
        is Condition.And -> condition.conditions.any(::isTemporal)
        is Condition.Or -> condition.conditions.any(::isTemporal)
        is Condition.Not -> isTemporal(condition.condition)
        else -> false
    }

    /** With [window] null, rate predicates are assumed to hold, whichever polarity they sit under. */
    private fun evaluateConditions(
        conditions: List<Condition>,
        packetInfo: Map<String, Any>,
        payload: ByteArray?,
        payloadStr: String?,
        window: SourceWindow?
    ): Boolean {
        // AND logic for top-level conditions
        return conditions.all { condition ->
            evaluateCondition(condition, packetInfo, payload, payloadStr, window, true)
        }
    }

    private fun evaluateCondition(
        condition: Condition,
        packetInfo: Map<String, Any>,
        payload: ByteArray?,
        payloadStr: String?,
        window: SourceWindow?,
        assume: Boolean
    ): Boolean {
        return when (condition) {
            is Condition.ProtocolEquals -> evaluateProtocolEquals(condition, packetInfo)
            is Condition.PortEquals -> evaluatePortEquals(condition, packetInfo)
            is Condition.PortInRange -> evaluatePortInRange(condition, packetInfo)
            is Condition.IpEquals -> evaluateIpEquals(condition, packetInfo)
            is Condition.IpInCidr -> evaluateIpInCidr(condition, packetInfo)
            is Condition.FlagsContain -> evaluateFlagsContain(condition, packetInfo)
            is Condition.DirectionEquals -> evaluateDirectionEquals(condition, packetInfo)
            is Condition.PayloadSize -> evaluatePayloadSize(condition, packetInfo, payload)
            is Condition.PayloadContains -> evaluatePayloadContains(condition, payloadStr)
            is Condition.PayloadMatches -> evaluatePayloadMatches(condition, payloadStr)
            is Condition.HeaderExists -> evaluateHeaderExists(condition, packetInfo)
            is Condition.HeaderEquals -> evaluateHeaderEquals(condition, packetInfo)
            is Condition.HeaderMatches -> evaluateHeaderMatches(condition, packetInfo)
            is Condition.PacketRate -> if (window == null) assume else evaluatePacketRate(condition, window)
            is Condition.ByteRate -> if (window == null) assume else evaluateByteRate(condition, window, packetInfo)
            is Condition.UniqueDestinations -> if (window == null) assume else evaluateUniqueDestinations(condition, window, packetInfo)
            is Condition.TimeSince -> evaluateTimeSince(condition)
            is Condition.And -> condition.conditions.all { evaluateCondition(it, packetInfo, payload, payloadStr, window, assume) }
            is Condition.Or -> condition.conditions.any { evaluateCondition(it, packetInfo, payload, payloadStr, window, assume) }
            is Condition.Not -> !evaluateCondition(condition.condition, packetInfo, payload, payloadStr, window, !assume)
            is Condition.DomainEquals -> evaluateDomainEquals(condition, packetInfo)
            is Condition.DomainContains -> evaluateDomainContains(condition, packetInfo)
            is Condition.DomainMatches -> evaluateDomainMatches(condition, packetInfo)
            is Condition.DnsQueryType -> evaluateDnsQueryType(condition, packetInfo)
            is Condition.DnsResponseCount -> evaluateDnsResponseCount(condition, packetInfo)
            is Condition.HttpMethod -> evaluateHttpMethod(condition, packetInfo)
            is Condition.HttpStatus -> evaluateHttpStatus(condition, packetInfo)
            is Condition.UrlContains -> evaluateUrlContains(condition, packetInfo)
            is Condition.UrlMatches -> evaluateUrlMatches(condition, packetInfo)
        }
    }

    // Evaluation helper functions
    private fun evaluateProtocolEquals(condition: Condition.ProtocolEquals, packetInfo: Map<String, Any>): Boolean {
        val protocol = packetInfo["protocol"]?.toString() ?: ""
        return protocol.equals(condition.protocol, ignoreCase = true)
    }

    private fun evaluatePortEquals(condition: Condition.PortEquals, packetInfo: Map<String, Any>): Boolean {
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
        return when (condition.direction) {
            Direction.DESTINATION -> destPort == condition.port
            Direction.SOURCE -> sourcePort == condition.port
            Direction.BOTH -> destPort == condition.port || sourcePort == condition.port
        }
    }

    private fun evaluatePortInRange(condition: Condition.PortInRange, packetInfo: Map<String, Any>): Boolean {
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
        val inRange = { port: Int -> port in condition.start..condition.end }
        return when (condition.direction) {
            Direction.DESTINATION -> inRange(destPort)
            Direction.SOURCE -> inRange(sourcePort)
            Direction.BOTH -> inRange(destPort) || inRange(sourcePort)
        }
    }

    private fun evaluateIpEquals(condition: Condition.IpEquals, packetInfo: Map<String, Any>): Boolean {
        val destIp = packetInfo["destinationIp"]?.toString() ?: ""
        val sourceIp = packetInfo["sourceIp"]?.toString() ?: ""
        return when (condition.direction) {
            Direction.DESTINATION -> destIp == condition.ip
            Direction.SOURCE -> sourceIp == condition.ip
            Direction.BOTH -> destIp == condition.ip || sourceIp == condition.ip
        }
    }

    private fun evaluateIpInCidr(condition: Condition.IpInCidr, packetInfo: Map<String, Any>): Boolean {
        val destIp = packetInfo["destinationIp"]?.toString() ?: ""
        val sourceIp = packetInfo["sourceIp"]?.toString() ?: ""
        return when (condition.direction) {
            Direction.DESTINATION -> ipv4InCidr(destIp, condition.cidr)
            Direction.SOURCE -> ipv4InCidr(sourceIp, condition.cidr)
            Direction.BOTH -> ipv4InCidr(destIp, condition.cidr) || ipv4InCidr(sourceIp, condition.cidr)
        }
    }

    private fun ipv4ToInt(ip: String): Int? {
        val parts = ip.split('.')
        if (parts.size != 4) return null
        var value = 0
        for (part in parts) {
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet
        }
        return value
    }

    private fun ipv4InCidr(ip: String, cidr: String): Boolean {
        val address = ipv4ToInt(ip) ?: return false
        val network = ipv4ToInt(cidr.substringBefore('/')) ?: return false
        val bits = cidr.substringAfter('/', "32").toIntOrNull() ?: return false
        if (bits !in 0..32) return false
        val mask = if (bits == 0) 0 else -1 shl (32 - bits)
        return (address and mask) == (network and mask)
    }

    private fun evaluateFlagsContain(condition: Condition.FlagsContain, packetInfo: Map<String, Any>): Boolean {
        val flags = packetInfo["flags"]?.toString() ?: ""
        return condition.flags.any { wanted ->
            // A NULL scan is the absence of every flag, so there is no name to search for
            if (wanted == "NULL") flags.isBlank() else flags.contains(wanted, ignoreCase = true)
        }
    }

    private fun evaluateDirectionEquals(condition: Condition.DirectionEquals, packetInfo: Map<String, Any>): Boolean {
        return packetInfo["direction"]?.toString().equals(condition.direction, ignoreCase = true)
    }

    private fun evaluatePayloadSize(condition: Condition.PayloadSize, packetInfo: Map<String, Any>, payload: ByteArray?): Boolean {
        // The record carries the size even when an encrypted payload is withheld from matching
        val size = (packetInfo["payloadSize"] as? Int) ?: payload?.size ?: 0
        return compareWithOperator(size, condition.size, condition.operator)
    }

    private fun evaluatePayloadContains(condition: Condition.PayloadContains, payloadStr: String?): Boolean {
        if (payloadStr == null) return false
        return payloadStr.lowercase().contains(condition.pattern.lowercase())
    }

    private fun evaluatePayloadMatches(condition: Condition.PayloadMatches, payloadStr: String?): Boolean {
        if (payloadStr == null) return false
        return condition.regex.containsMatchIn(payloadStr)
    }

    private fun evaluateHeaderExists(condition: Condition.HeaderExists, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        return httpData.containsKey(condition.header)
    }

    private fun evaluateHeaderEquals(condition: Condition.HeaderEquals, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val headerValue = httpData[condition.header]?.toString() ?: return false
        return headerValue.equals(condition.value, ignoreCase = true)
    }

    private fun evaluateHeaderMatches(condition: Condition.HeaderMatches, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val headerValue = httpData[condition.header]?.toString() ?: return false
        return condition.regex.containsMatchIn(headerValue)
    }

    private fun evaluateByteRate(condition: Condition.ByteRate, window: SourceWindow, packetInfo: Map<String, Any>): Boolean {
        val recentBytes = window.bytesSince(PacketClock.now() - condition.windowMs, packetInfo["destinationIp"]?.toString() ?: "")
        return compareWithOperator(recentBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), condition.bytes.toInt(), condition.operator)
    }

    private fun evaluatePacketRate(condition: Condition.PacketRate, window: SourceWindow): Boolean {
        val recentPackets = window.countSince(PacketClock.now() - condition.windowMs)
        return compareWithOperator(recentPackets, condition.count, condition.operator)
    }

    private fun evaluateUniqueDestinations(condition: Condition.UniqueDestinations, window: SourceWindow, packetInfo: Map<String, Any>): Boolean {
        val uniqueDests = window.uniqueDestinationsSince(PacketClock.now() - condition.windowMs)
        return compareWithOperator(uniqueDests, (condition.count * AppContext.limitFactor(packetInfo)).toInt(), condition.operator)
    }

    /** Time since the rule named by [Condition.TimeSince.event] last fired; never-fired counts as forever. */
    private fun evaluateTimeSince(condition: Condition.TimeSince): Boolean {
        val last = ruleState[condition.event]?.lastTriggered ?: 0L
        val elapsed = if (last == 0L) Long.MAX_VALUE else PacketClock.now() - last
        return compareWithOperator(elapsed, condition.durationMs, condition.operator)
    }

    private fun evaluateDnsQueryType(condition: Condition.DnsQueryType, packetInfo: Map<String, Any>): Boolean {
        val dnsData = packetInfo["dnsData"] as? Map<*, *> ?: return false
        val queryType = dnsData["queryType"]?.toString() ?: return false
        // The dissector renders some types with a gloss, e.g. "A (IPv4)"
        return queryType.substringBefore(' ').equals(condition.type, ignoreCase = true)
    }

    private fun evaluateDnsResponseCount(condition: Condition.DnsResponseCount, packetInfo: Map<String, Any>): Boolean {
        val dnsData = packetInfo["dnsData"] as? Map<*, *> ?: return false
        if (dnsData["type"] != "Response") return false
        val answers = dnsData["answers"]?.toString()?.toIntOrNull() ?: return false
        return compareWithOperator(answers, condition.count, condition.operator)
    }

    private fun evaluateHttpStatus(condition: Condition.HttpStatus, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<*, *> ?: return false
        val status = httpData["statusCode"]?.toString()?.toIntOrNull() ?: return false
        return compareWithOperator(status, condition.status, condition.operator)
    }

    private fun evaluateDomainEquals(condition: Condition.DomainEquals, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString() ?: ""
        return domain.equals(condition.domain, ignoreCase = true)
    }

    private fun evaluateDomainContains(condition: Condition.DomainContains, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString() ?: ""
        return domain.contains(condition.substring, ignoreCase = true)
    }

    private fun evaluateDomainMatches(condition: Condition.DomainMatches, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString() ?: ""
        return condition.regex.containsMatchIn(domain)
    }

    private fun evaluateHttpMethod(condition: Condition.HttpMethod, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val method = httpData["method"]?.toString() ?: ""
        return method.equals(condition.method, ignoreCase = true)
    }

    private fun evaluateUrlContains(condition: Condition.UrlContains, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val url = httpData["url"]?.toString() ?: ""
        return url.contains(condition.substring, ignoreCase = true)
    }

    private fun evaluateUrlMatches(condition: Condition.UrlMatches, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val url = httpData["url"]?.toString() ?: ""
        return condition.regex.containsMatchIn(url)
    }

    private fun compareWithOperator(actual: Int, expected: Int, operator: Operator): Boolean =
        compareWithOperator(actual.toLong(), expected.toLong(), operator)

    private fun compareWithOperator(actual: Long, expected: Long, operator: Operator): Boolean {
        return when (operator) {
            Operator.EQUALS -> actual == expected
            Operator.NOT_EQUALS -> actual != expected
            Operator.GREATER_THAN -> actual > expected
            Operator.LESS_THAN -> actual < expected
            Operator.GREATER_EQUAL -> actual >= expected
            Operator.LESS_EQUAL -> actual <= expected
        }
    }

    private fun buildMatchDetails(rule: Rule, packetInfo: Map<String, Any>): Map<String, Any> {
        return mapOf(
            "ruleId" to rule.id,
            "ruleName" to rule.name,
            "category" to rule.category,
            "sourceIp" to (packetInfo["sourceIp"] ?: ""),
            "destinationIp" to (packetInfo["destinationIp"] ?: ""),
            "protocol" to (packetInfo["protocol"] ?: "")
        )
    }

    private fun executeAction(action: Action, packetInfo: Map<String, Any>) {
        when (action) {
            is Action.Alert -> Log.w(TAG, "Rule triggered")
            is Action.AlertWithDetails -> Log.w(TAG, "Rule triggered: ${action.message}")
            is Action.Block -> Log.w(TAG, "Blocking action not implemented")
            is Action.Log -> Log.i(TAG, "Rule matched: $packetInfo")
            is Action.Custom -> action.handler(packetInfo)
        }
    }

    data class RuleMatch(
        val rule: Rule,
        val timestamp: Long,
        val details: Map<String, Any>
    )

    /**
     * Add custom rule
     */
    fun addRule(rule: Rule) {
        rules.add(rule)
        Log.i(TAG, "Added rule: ${rule.id} - ${rule.name}")
    }

    /**
     * Get statistics
     */
    fun getStatistics(): Map<String, Any> = mapOf(
        "totalRules" to rules.size,
        "enabledRules" to rules.count { it.enabled },
        "byCategory" to rules.groupBy { it.category }.mapValues { it.value.size },
        "bySeverity" to rules.groupBy { it.severity }.mapValues { it.value.size }
    )

    /**
     * Clear rule state
     */
    fun clearState() {
        ruleState.clear()
        Log.i(TAG, "Rule state cleared")
    }
}
