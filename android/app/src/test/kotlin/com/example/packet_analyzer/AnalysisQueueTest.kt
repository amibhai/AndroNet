package com.example.packet_analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class AnalysisQueueTest {
    private val packet = ByteArray(100)

    @Test
    fun `a full queue skips and counts packets instead of blocking the relay`() {
        val release = CountDownLatch(1)
        val queue = AnalysisQueue({ release.await() }, capacity = 4)
        queue.start()

        val start = System.nanoTime()
        val accepted = (1..100).count { queue.offer(packet, true, 1L) }
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)

        assertTrue("offer must not wait for the consumer, took $elapsedMs ms", elapsedMs < 1000)
        assertEquals(100L - accepted, queue.skippedPackets)
        assertTrue(queue.skippedPackets > 0)
        release.countDown()
        queue.stop()
    }

    @Test
    fun `the byte budget bounds memory whatever the packet count`() {
        val release = CountDownLatch(1)
        val queue = AnalysisQueue({ release.await() }, maxBytes = 1000)
        queue.start()

        repeat(50) { queue.offer(packet, true, 1L) }

        assertTrue("about 10 of 50 fit in 1000 bytes", queue.skippedPackets >= 35)
        release.countDown()
        queue.stop()
    }

    @Test
    fun `stop analyses what was already queued`() {
        val analysed = AtomicInteger(0)
        val queue = AnalysisQueue({ analysed.incrementAndGet() })
        queue.start()

        repeat(500) { queue.offer(packet, false, 1L) }
        queue.stop()

        assertEquals(500, analysed.get())
    }

    @Test
    fun `a packet that makes analysis fail does not end it`() {
        val analysed = AtomicInteger(0)
        val queue = AnalysisQueue({
            if (analysed.incrementAndGet() == 1) throw IllegalStateException("bad packet")
        })
        queue.start()

        repeat(10) { queue.offer(packet, true, 1L) }
        queue.stop()

        assertEquals(10, analysed.get())
    }

    @Test
    fun `packets offered after stop are refused`() {
        val queue = AnalysisQueue({})
        queue.start()
        queue.stop()

        assertFalse(queue.offer(packet, true, 1L))
    }

    @Test
    fun `skipped packets are reported as an overload`() {
        val reported = AtomicLong(0)
        val release = CountDownLatch(1)
        val queue = AnalysisQueue({ release.await() }, { reported.addAndGet(it) }, capacity = 2)
        queue.start()

        repeat(20) { queue.offer(packet, true, 60_000L) }
        val skipped = queue.skippedPackets
        release.countDown()
        queue.stop()

        assertTrue(skipped > 0)
        assertEquals(skipped, reported.get())
    }
}
