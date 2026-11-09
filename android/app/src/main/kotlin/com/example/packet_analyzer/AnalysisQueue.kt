package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Hands captured packets from the relay to the analysis thread. Forwarding must never wait for
 * analysis, so a packet that finds the queue full is skipped and counted. Skipped packets are a blind
 * spot an attacker could try to cause on purpose, so the count is reported through [onOverload].
 */
class AnalysisQueue(
    private val consumer: (Item) -> Unit,
    private val onOverload: (Long) -> Unit = {},
    capacity: Int = DEFAULT_CAPACITY,
    private val maxBytes: Long = DEFAULT_MAX_BYTES
) {
    class Item(val packet: ByteArray, val isOutgoing: Boolean, val capturedAtMs: Long)

    private val queue = ArrayBlockingQueue<Item>(capacity)
    private val queuedBytes = AtomicLong(0)
    private val skipped = AtomicLong(0)
    private val accepted = AtomicLong(0)
    private var reportedSkipped = 0L
    private var lastReportMs = 0L

    @Volatile private var running = false
    private var worker: Thread? = null

    val skippedPackets: Long get() = skipped.get()
    val acceptedPackets: Long get() = accepted.get()

    fun start() {
        if (running) return
        running = true
        worker = Thread({ drain() }, "packet-analysis").apply {
            isDaemon = true
            start()
        }
    }

    /** Never blocks. Returns false when the packet was skipped. */
    fun offer(packet: ByteArray, isOutgoing: Boolean, capturedAtMs: Long): Boolean {
        if (!running) return false
        if (queuedBytes.get() + packet.size > maxBytes || !queue.offer(Item(packet, isOutgoing, capturedAtMs))) {
            skipped.incrementAndGet()
            return false
        }
        queuedBytes.addAndGet(packet.size.toLong())
        accepted.incrementAndGet()
        return true
    }

    /** Stops accepting packets and returns once what was already queued has been analysed. */
    fun stop() {
        running = false
        worker?.join(STOP_WAIT_MS)
        worker = null
    }

    private fun drain() {
        while (running || queue.isNotEmpty()) {
            val item = queue.poll(POLL_MS, TimeUnit.MILLISECONDS) ?: continue
            queuedBytes.addAndGet(-item.packet.size.toLong())
            // One bad packet must not end analysis: with this thread gone, every later packet
            // would be skipped and nothing would say so
            try {
                consumer(item)
                reportOverload(item.capturedAtMs)
            } catch (e: Exception) {
                Log.e(TAG, "Analysis failed on one packet: ${e.message}")
            }
        }
    }

    private fun reportOverload(nowMs: Long) {
        val total = skipped.get()
        if (total == reportedSkipped || nowMs - lastReportMs < REPORT_INTERVAL_MS) return
        lastReportMs = nowMs
        onOverload(total - reportedSkipped)
        reportedSkipped = total
    }

    companion object {
        private const val TAG = "AnalysisQueue"
        private const val DEFAULT_CAPACITY = 8192
        private const val DEFAULT_MAX_BYTES = 32L * 1024 * 1024
        private const val POLL_MS = 100L
        private const val STOP_WAIT_MS = 2_000L
        private const val REPORT_INTERVAL_MS = 10_000L
    }
}
