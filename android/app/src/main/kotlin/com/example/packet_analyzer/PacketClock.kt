package com.example.packet_analyzer

/**
 * The time detection runs on. Analysis sits behind a queue, so rate windows have to follow when a
 * packet was captured: judged at dequeue time, a backlog drained in one burst would read as a flood,
 * and an analyser falling behind would see a real flood as a trickle.
 */
object PacketClock {
    @Volatile private var captureTimeMs = 0L

    fun set(timeMs: Long) {
        captureTimeMs = timeMs
    }

    fun reset() {
        captureTimeMs = 0L
    }

    fun now(): Long = if (captureTimeMs != 0L) captureTimeMs else System.currentTimeMillis()
}
