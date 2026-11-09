package com.andronet.eval

import com.example.packet_analyzer.AnomalyDetector
import com.example.packet_analyzer.EvalClock
import com.example.packet_analyzer.RuleEngine
import com.example.packet_analyzer.SignatureDatabase
import com.example.packet_analyzer.TrafficStatistics
import java.io.File
import java.io.PrintWriter
import java.util.PriorityQueue

/**
 * Replays labelled captures through the production detection classes and writes results as JSON.
 *
 *   accuracy  --thresholds shipped|fixed --spec name=path:label[@offsetSeconds],... --out f.json
 *   cost      --trace path --limit N --repeat K --out f.json
 *
 * Runs on a desktop JVM and, unmodified, under app_process on the phone (ART, ICU regex).
 */

private class Stream(val reader: PcapReader, val name: String, val label: String, offsetUs: Long, zero: Long?) {
    var head: Frame? = reader.read()
    val shift: Long = if (zero == null || head == null) 0L else zero + offsetUs - head!!.tsUs
    fun ts(): Long = head!!.tsUs + shift
}

private class AlertRec(val id: String, val layer: Int, val severity: String)

private val tagged = Regex("^\\[([A-Z0-9-]+)\\]")

private fun toAlert(a: AnomalyDetector.Anomaly): AlertRec {
    val m = tagged.find(a.description)
    if (m != null) {
        val id = m.groupValues[1]
        return AlertRec(id, if (id.startsWith("RULE-")) 3 else 2, a.severity.name)
    }
    return AlertRec("L1:" + a.type.name, 1, a.severity.name)
}

private fun isOutgoing(record: Map<String, Any>): Boolean {
    val src = record["sourcePort"] as? Int ?: 0
    val dst = record["destinationPort"] as? Int ?: 0
    return dst in 1..src
}

private fun outgoingFromRaw(unit: NetUnit): Boolean {
    val p = (unit as? NetUnit.Ip)?.packet ?: return true
    return try {
        val off = if ((p[0].toInt() shr 4) and 0xF == 4) (p[0].toInt() and 0xF) * 4 else 40
        val src = ((p[off].toInt() and 0xFF) shl 8) or (p[off + 1].toInt() and 0xFF)
        val dst = ((p[off + 2].toInt() and 0xFF) shl 8) or (p[off + 3].toInt() and 0xFF)
        dst <= src
    } catch (e: Exception) {
        true
    }
}

private fun jsonEsc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")

private fun clearDetectionLists(signatures: Boolean, rules: Boolean) {
    if (signatures) {
        val f = SignatureDatabase::class.java.getDeclaredField("signatures")
        f.isAccessible = true
        (f.get(SignatureDatabase) as MutableList<*>).clear()
    }
    if (rules) {
        val f = RuleEngine::class.java.getDeclaredField("rules")
        f.isAccessible = true
        (f.get(RuleEngine) as MutableList<*>).clear()
    }
}

private fun startSession(thresholds: String, firstTsMs: Long) {
    Pipeline.reset()
    if (thresholds == "shipped") {
        // MainActivity.startAnomalyDetection() opens a 60 s learning period on every capture start.
        // Start it a minute before the first frame so a short scenario is not swallowed whole.
        EvalClock.nowMs = firstTsMs - 61_000L
        AnomalyDetector.adaptiveThresholds.startLearning()
    }
    EvalClock.nowMs = firstTsMs
}

private fun runAccuracy(spec: String, thresholds: String, view: String, outPath: String, alertLog: String?) {
    val parts = spec.split(",").filter { it.isNotBlank() }
    val log = alertLog?.let { PrintWriter(File(it)) }

    val listeners = ArrayList<AlertRec>()
    AnomalyDetector.addAnomalyListener { a -> listeners.add(toAlert(a)) }

    val out = StringBuilder("{\"pipeline\":\"${Pipeline.NAME}\",\"thresholds\":\"$thresholds\",\"view\":\"$view\",\"runs\":[")
    var firstRun = true

    for (entry in parts) {
        // name=sourceA:labelA[@offset]+sourceB:labelB[@offset]; a '+' replays the sources merged
        val name = entry.substringBefore("=")
        val sources = entry.substringAfter("=").split("+")
        val parsed = sources.map { s ->
            val offset = s.substringAfterLast("@", "").toDoubleOrNull()
            val bare = if (offset != null) s.substringBeforeLast("@") else s
            Triple(bare.substringBeforeLast(":"), bare.substringAfterLast(":"), offset ?: 0.0)
        }

        val heads = parsed.map { (path, label, offset) -> PcapReader(File(path)).let { r -> Triple(r, label, offset) } }
        var zero: Long? = null
        val queue = PriorityQueue<Stream>(compareBy { it.ts() })
        for ((i, h) in heads.withIndex()) {
            val st = Stream(h.first, parsed[i].first, h.second, (h.third * 1e6).toLong(), zero)
            if (st.head != null) {
                if (zero == null) zero = st.head!!.tsUs
                queue.add(st)
            }
        }
        val first = queue.peek()
        if (first == null) continue
        startSession(thresholds, first.ts() / 1000)

        val perLabelPackets = HashMap<String, Long>()
        val perLabelFlagged = HashMap<String, LongArray>() // any, L1, L2, L3
        val alertCounts = HashMap<String, HashMap<String, Long>>() // label -> id -> n
        val sevCounts = HashMap<String, Long>()
        var dropped = 0L
        var total = 0L
        var firstTs = Long.MAX_VALUE
        var lastTs = 0L

        while (queue.isNotEmpty()) {
            val st = queue.poll()
            val f = st.head!!
            val ts = st.ts()
            EvalClock.nowMs = ts / 1000
            if (ts < firstTs) firstTs = ts
            if (ts > lastTs) lastTs = ts

            val unit = LinkLayer.strip(f)
            if (unit == null) {
                dropped++
            } else {
                val record = Pipeline.buildRecord(unit, outgoingFromRaw(unit), view)
                if (record == null) {
                    dropped++
                } else {
                    total++
                    perLabelPackets.merge(st.label, 1L, Long::plus)
                    listeners.clear()
                    TrafficStatistics.updateStats(record)
                    val (finalPacket, payload) = Pipeline.dissectAndEnrich(record, Pipeline.rawOf(unit))
                    Pipeline.analyze(finalPacket, payload)
                    if (listeners.isNotEmpty()) {
                        val flags = perLabelFlagged.getOrPut(st.label) { LongArray(4) }
                        flags[0]++
                        val seen = BooleanArray(4)
                        for (a in listeners) {
                            if (!seen[a.layer]) { flags[a.layer]++; seen[a.layer] = true }
                            alertCounts.getOrPut(st.label) { HashMap() }.merge(a.id, 1L, Long::plus)
                            sevCounts.merge(a.severity, 1L, Long::plus)
                            log?.println("$name\t${st.label}\t$total\t${ts / 1000}\t${a.id}\t${a.severity}")
                        }
                    }
                }
            }
            st.head = st.reader.read()
            if (st.head != null) queue.add(st) else st.reader.close()
        }

        if (!firstRun) out.append(",")
        firstRun = false
        out.append("{\"name\":\"${jsonEsc(name)}\",\"packets\":$total,\"dropped\":$dropped,\"durationSec\":${(lastTs - firstTs) / 1e6},")
        out.append("\"thresholdsEnd\":{")
        val t = AnomalyDetector.adaptiveThresholds
        out.append("\"portScan\":${t.portScanThreshold},\"synFlood\":${t.synFloodThreshold},\"connectionRate\":${t.connectionRateThreshold}},")
        out.append("\"labels\":{")
        out.append(perLabelPackets.entries.joinToString(",") { (label, n) ->
            val fl = perLabelFlagged[label] ?: LongArray(4)
            val alerts = alertCounts[label]?.entries?.joinToString(",") { "\"${jsonEsc(it.key)}\":${it.value}" } ?: ""
            "\"${jsonEsc(label)}\":{\"packets\":$n,\"flagged\":{\"any\":${fl[0]},\"L1\":${fl[1]},\"L2\":${fl[2]},\"L3\":${fl[3]}},\"alerts\":{$alerts}}"
        })
        out.append("},\"severity\":{")
        out.append(sevCounts.entries.joinToString(",") { "\"${it.key}\":${it.value}" })
        out.append("}}")
        println("[accuracy] $name packets=$total dropped=$dropped alerts=${alertCounts.values.sumOf { m -> m.values.sum() }}")
    }
    out.append("]}")
    File(outPath).writeText(out.toString())
    log?.close()
}

private fun quantile(sorted: LongArray, q: Double): Long =
    if (sorted.isEmpty()) 0L else sorted[((sorted.size - 1) * q).toInt()]

private class Prepared(val unit: NetUnit, val tsMs: Long)

private fun loadPrepared(path: String, limit: Int): List<Prepared> {
    val res = ArrayList<Prepared>()
    PcapReader(File(path)).use { r ->
        while (res.size < limit) {
            val f = r.read() ?: break
            val u = LinkLayer.strip(f) ?: continue
            res.add(Prepared(u, f.tsUs / 1000))
        }
    }
    return res
}

/**
 * Per-stage cost. Layers are costed by ablation: the same trace is replayed with the signature
 * and rule lists emptied by reflection, so L1 = T(no lists), L2 = T(no rules) - L1, and
 * L3 = T(full) - T(no rules). The production code itself carries no timers.
 */
private fun runCost(path: String, limit: Int, repeat: Int, outPath: String, thresholds: String) {
    val frames = loadPrepared(path, limit)
    val n = frames.size
    println("[cost] loaded $n packets from $path")
    val sink = ArrayList<AlertRec>()
    AnomalyDetector.addAnomalyListener { a -> sink.add(toAlert(a)) }

    // Taken first, while the signature and rule lists are still intact
    val heap = heapAfterReplay(frames, thresholds)

    val stages = listOf("full", "noRules", "noRulesNoSigs")
    val result = LinkedHashMap<String, Map<String, Double>>()

    // The lists are emptied in order, so run the configuration with everything first.
    for (stage in stages) {
        if (stage == "noRules") clearDetectionLists(signatures = false, rules = true)
        if (stage == "noRulesNoSigs") clearDetectionLists(signatures = true, rules = true)
        val samplesParse = LongArray(n)
        val samplesStats = LongArray(n)
        val samplesDpi = LongArray(n)
        val samplesDetect = LongArray(n)
        val samplesTotal = LongArray(n)
        val wall = ArrayList<Double>()
        var alerts = 0L

        for (rep in 0 until repeat + 1) { // the first pass is JIT warm-up and is discarded
            startSession(thresholds, frames.firstOrNull()?.tsMs ?: 0L)
            val base = frames.firstOrNull()?.tsMs ?: 0L
            sink.clear()
            val t0 = System.nanoTime()
            for (i in 0 until n) {
                val p = frames[i]
                EvalClock.nowMs = p.tsMs
                val a = System.nanoTime()
                val record = Pipeline.buildRecord(p.unit, outgoingFromRaw(p.unit), "all")
                val b = System.nanoTime()
                if (record == null) continue
                TrafficStatistics.updateStats(record)
                val c = System.nanoTime()
                val (finalPacket, payload) = Pipeline.dissectAndEnrich(record, Pipeline.rawOf(p.unit))
                val d = System.nanoTime()
                Pipeline.analyze(finalPacket, payload)
                val e = System.nanoTime()
                if (rep > 0) {
                    samplesParse[i] = maxOf(samplesParse[i], 0L) + (b - a)
                    samplesStats[i] += c - b
                    samplesDpi[i] += d - c
                    samplesDetect[i] += e - d
                    samplesTotal[i] += e - a
                }
            }
            val secs = (System.nanoTime() - t0) / 1e9
            if (rep > 0) wall.add(secs)
            alerts = sink.size.toLong()
        }
        val div = repeat.toLong()
        fun summary(arr: LongArray): Map<String, Double> {
            val per = LongArray(n) { arr[it] / div }
            val sorted = per.sortedArray()
            return mapOf(
                "meanUs" to per.average() / 1000.0,
                "p50Us" to quantile(sorted, 0.50) / 1000.0,
                "p95Us" to quantile(sorted, 0.95) / 1000.0,
                "p99Us" to quantile(sorted, 0.99) / 1000.0,
                "maxUs" to (sorted.lastOrNull() ?: 0L) / 1000.0
            )
        }
        result["$stage.parse"] = summary(samplesParse)
        result["$stage.stats"] = summary(samplesStats)
        result["$stage.dpi"] = summary(samplesDpi)
        result["$stage.detect"] = summary(samplesDetect)
        result["$stage.total"] = summary(samplesTotal)
        val bestWall = wall.minOrNull() ?: 0.0
        result["$stage.wall"] = mapOf(
            "bestSec" to bestWall,
            "medianSec" to (wall.sorted().getOrElse(wall.size / 2) { 0.0 }),
            "packets" to n.toDouble(),
            "bestPps" to if (bestWall > 0) n / bestWall else 0.0,
            "alerts" to alerts.toDouble()
        )
        println("[cost] $stage detect mean=${"%.1f".format(result["$stage.detect"]!!["meanUs"])} us, total mean=${"%.1f".format(result["$stage.total"]!!["meanUs"])} us, best=${"%.0f".format(result["$stage.wall"]!!["bestPps"])} pps")
    }

    val json = StringBuilder("{\"pipeline\":\"${Pipeline.NAME}\",\"trace\":\"${jsonEsc(File(path).name)}\",\"packets\":$n,\"repeat\":$repeat,\"thresholds\":\"$thresholds\",")
    json.append("\"heap\":{").append(heap.entries.joinToString(",") { "\"${it.key}\":${it.value}" }).append("},")
    json.append("\"stages\":{")
    json.append(result.entries.joinToString(",") { (k, v) -> "\"$k\":{" + v.entries.joinToString(",") { "\"${it.key}\":${"%.3f".format(java.util.Locale.ROOT, it.value)}" } + "}" })
    json.append("}}")
    File(outPath).writeText(json.toString())
}

/** Retained heap of the detection state after replaying the trace once. */
private fun heapAfterReplay(frames: List<Prepared>, thresholds: String): Map<String, Long> {
    val rt = Runtime.getRuntime()
    fun used(): Long {
        repeat(3) { System.gc(); System.runFinalization(); Thread.sleep(50) }
        return rt.totalMemory() - rt.freeMemory()
    }
    val before = used()
    startSession(thresholds, frames.firstOrNull()?.tsMs ?: 0L)
    for (p in frames) {
        EvalClock.nowMs = p.tsMs
        val record = Pipeline.buildRecord(p.unit, outgoingFromRaw(p.unit), "all") ?: continue
        TrafficStatistics.updateStats(record)
        val (finalPacket, payload) = Pipeline.dissectAndEnrich(record, Pipeline.rawOf(p.unit))
        Pipeline.analyze(finalPacket, payload)
    }
    val after = used()
    return mapOf("beforeBytes" to before, "afterBytes" to after, "deltaBytes" to (after - before))
}

/** One line per ClientHello: frame number, JA3, JA4. check_fingerprints.py compares them with Wireshark's. */
private fun printFingerprints(path: String) {
    Pipeline.reset()
    PcapReader(File(path)).use { reader ->
        var frame = 0
        while (true) {
            val f = reader.read() ?: break
            frame++
            val unit = LinkLayer.strip(f) ?: continue
            val record = Pipeline.buildRecord(unit, true, "root") ?: continue
            val (enriched, _) = Pipeline.dissectAndEnrich(record, Pipeline.rawOf(unit))
            val tls = enriched["tlsData"] as? Map<*, *> ?: continue
            val ja3 = tls["ja3"] ?: continue
            println("$frame $ja3 ${tls["ja4"]}")
        }
    }
}

fun main(args: Array<String>) {
    val mode = args.getOrNull(0) ?: "accuracy"
    fun opt(k: String, d: String? = null): String? {
        val i = args.indexOf("--$k")
        return if (i >= 0 && i + 1 < args.size) args[i + 1] else d
    }
    when (mode) {
        "accuracy" -> runAccuracy(
            spec = if (opt("specfile") != null) File(opt("specfile")!!).readText().trim() else opt("spec")!!,
            thresholds = opt("thresholds", "shipped")!!,
            view = opt("view", "vpn")!!,
            outPath = opt("out", "accuracy.json")!!,
            alertLog = opt("alerts")
        )
        "cost" -> runCost(
            path = opt("trace")!!,
            limit = opt("limit", "20000")!!.toInt(),
            repeat = opt("repeat", "3")!!.toInt(),
            outPath = opt("out", "cost.json")!!,
            thresholds = opt("thresholds", "fixed")!!
        )
        "fingerprints" -> printFingerprints(opt("trace")!!)
        "livegen" -> LiveGen.run(opt("host")!!, opt("only"), opt("out", "live.txt")!!, opt("settle", "11000")!!.toLong())
        "transfer" -> {
            val host = opt("host")!!
            val direction = opt("direction", "down")!!
            val megabytes = opt("mb", "100")!!.toLong()
            repeat(opt("repeat", "3")!!.toInt()) {
                println("transfer $direction ${"%.1f".format(java.util.Locale.ROOT, LiveGen.transfer(host, direction, megabytes * 1024 * 1024))} Mbit/s")
                Thread.sleep(1000)
            }
        }
        "rtt" -> {
            val rtts = LiveGen.connectRtt(opt("host")!!, opt("samples", "50")!!.toInt()).sorted()
            println("rtt p50=${"%.2f".format(java.util.Locale.ROOT, rtts[rtts.size / 2])} p95=${"%.2f".format(java.util.Locale.ROOT, rtts[rtts.size * 95 / 100])} min=${"%.2f".format(java.util.Locale.ROOT, rtts.first())} ms")
        }
        "info" -> {
            println("pipeline=${Pipeline.NAME}")
            println("signatures=${SignatureDatabase.getStatistics()}")
            println("rules=${RuleEngine.getStatistics()}")
        }
        else -> error("unknown mode $mode")
    }
}
