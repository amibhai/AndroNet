package com.example.packet_analyzer

/**
 * How far each flow's payload has been inspected. Attacks tend to announce themselves early: request
 * lines, handshakes and tool banners sit in a flow's first bytes, and the rest of a long flow is bulk
 * data. Past its depth a flow keeps feeding header, rate and size checks but costs no payload work,
 * the trade Suricata makes with stream depth and encrypted-traffic bypass. A pattern placed after the
 * depth escapes matching, which is the price of this and a stated limit of the system.
 */
object FlowTable {
    const val DEPTH_CLEARTEXT = 64 * 1024
    const val DEPTH_ENCRYPTED = 8 * 1024
    private const val MAX_FLOWS = 4096
    private const val DNS_PORT = 53
    private const val TAIL_BYTES = 64
    private const val MAX_HELLO_BYTES = 16 * 1024

    enum class Verdict { FIRST_PAYLOAD, INSPECT, BEYOND_DEPTH }

    private class Flow {
        var forwardBytes = 0
        var reverseBytes = 0
        var forwardTail: ByteArray? = null
        var reverseTail: ByteArray? = null
        var startSeen = false
        var partialHello: ByteArray? = null
    }

    private val flows = object : LinkedHashMap<Long, Flow>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, Flow>?) = size > MAX_FLOWS
    }

    /** Counts this packet's payload against its flow's depth in this direction. */
    fun account(packetInfo: Map<String, Any>, payloadSize: Int): Verdict {
        val protocol = packetInfo["protocol"] as? String ?: return Verdict.INSPECT
        if (!protocol.contains("TCP") && !protocol.contains("UDP")) return Verdict.INSPECT

        val sourcePort = packetInfo["sourcePort"] as? Int ?: return Verdict.INSPECT
        val destPort = packetInfo["destinationPort"] as? Int ?: return Verdict.INSPECT
        // A DNS tunnel can keep one UDP socket open for as long as it likes, and queries are small
        if (protocol.contains("UDP") && (sourcePort == DNS_PORT || destPort == DNS_PORT)) return Verdict.INSPECT

        val a = (packetInfo["sourceIp"] as? String).hashCode() * 31 + sourcePort
        val b = (packetInfo["destinationIp"] as? String).hashCode() * 31 + destPort
        val flow = flows.getOrPut(keyOf(a, b, protocol)) { Flow() }
        // A capture can begin in the middle of a flow, and then its first bytes here say nothing
        val first = flow.startSeen && flow.forwardBytes == 0 && flow.reverseBytes == 0

        val encrypted = sourcePort in PacketDissector.ENCRYPTED_PORTS || destPort in PacketDissector.ENCRYPTED_PORTS
        val depth = if (encrypted) DEPTH_ENCRYPTED else DEPTH_CLEARTEXT
        if (a <= b) {
            if (flow.forwardBytes >= depth) return Verdict.BEYOND_DEPTH
            flow.forwardBytes += payloadSize
        } else {
            if (flow.reverseBytes >= depth) return Verdict.BEYOND_DEPTH
            flow.reverseBytes += payloadSize
        }
        return if (first) Verdict.FIRST_PAYLOAD else Verdict.INSPECT
    }

    /** A TCP handshake packet: this flow's first payload, when it comes, really is its first. */
    fun noteStart(packetInfo: Map<String, Any>) {
        val protocol = packetInfo["protocol"] as? String ?: return
        val sourcePort = packetInfo["sourcePort"] as? Int ?: return
        val destPort = packetInfo["destinationPort"] as? Int ?: return
        val a = (packetInfo["sourceIp"] as? String).hashCode() * 31 + sourcePort
        val b = (packetInfo["destinationIp"] as? String).hashCode() * 31 + destPort
        flows.getOrPut(keyOf(a, b, protocol)) { Flow() }.startSeen = true
    }

    fun shouldInspect(packetInfo: Map<String, Any>, payloadSize: Int) =
        account(packetInfo, payloadSize) != Verdict.BEYOND_DEPTH

    /**
     * This TCP segment with the end of the previous one in front of it, so that a pattern split across
     * two segments still matches. This is no reassembly: it assumes segments arrive in order, and it
     * bounds what a split can hide rather than rebuilding the stream.
     */
    fun withTail(packetInfo: Map<String, Any>, payload: ByteArray): ByteArray {
        val protocol = packetInfo["protocol"] as? String ?: return payload
        if (!protocol.contains("TCP")) return payload
        val sourcePort = packetInfo["sourcePort"] as? Int ?: return payload
        val destPort = packetInfo["destinationPort"] as? Int ?: return payload
        if (sourcePort in PacketDissector.ENCRYPTED_PORTS || destPort in PacketDissector.ENCRYPTED_PORTS) return payload

        val a = (packetInfo["sourceIp"] as? String).hashCode() * 31 + sourcePort
        val b = (packetInfo["destinationIp"] as? String).hashCode() * 31 + destPort
        val flow = flows[keyOf(a, b, protocol)] ?: return payload
        val forward = a <= b
        val tail = if (forward) flow.forwardTail else flow.reverseTail
        val keep = payload.copyOfRange(maxOf(0, payload.size - TAIL_BYTES), payload.size)
        if (forward) flow.forwardTail = keep else flow.reverseTail = keep
        return if (tail == null) payload else tail + payload
    }

    /**
     * Browsers split a large ClientHello across two segments on purpose, which would hide its name and
     * its fingerprint. Returns the whole hello when this segment completes one, and null otherwise.
     * Assumes the segments arrive in order, and gives up at a bound an attacker cannot make grow.
     */
    fun completeHello(packetInfo: Map<String, Any>, payload: ByteArray): ByteArray? {
        val protocol = packetInfo["protocol"] as? String ?: return null
        if (!protocol.contains("TCP")) return null
        val sourcePort = packetInfo["sourcePort"] as? Int ?: return null
        val destPort = packetInfo["destinationPort"] as? Int ?: return null
        val a = (packetInfo["sourceIp"] as? String).hashCode() * 31 + sourcePort
        val b = (packetInfo["destinationIp"] as? String).hashCode() * 31 + destPort
        val flow = flows[keyOf(a, b, protocol)] ?: return null

        val partial = flow.partialHello
        val joined = if (partial != null) partial + payload else payload
        if (partial == null && !startsClientHello(payload)) return null
        val needed = 5 + (((joined[3].toInt() and 0xFF) shl 8) or (joined[4].toInt() and 0xFF))
        return when {
            needed > MAX_HELLO_BYTES -> {
                flow.partialHello = null
                null
            }
            joined.size >= needed -> {
                flow.partialHello = null
                if (partial != null) joined else null
            }
            else -> {
                flow.partialHello = joined
                null
            }
        }
    }

    private fun startsClientHello(p: ByteArray) =
        p.size >= 6 && p[0].toInt() == 22 && p[1].toInt() == 3 && p[5].toInt() == 1

    private fun keyOf(a: Int, b: Int, protocol: String): Long =
        (minOf(a, b).toLong() shl 32) xor (maxOf(a, b).toLong() and 0xFFFFFFFFL) xor protocol.hashCode().toLong()

    fun reset() {
        flows.clear()
    }
}
