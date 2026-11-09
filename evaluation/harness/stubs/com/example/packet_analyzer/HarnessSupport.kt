package com.example.packet_analyzer

/**
 * Stand-ins needed to compile the production detection sources outside Gradle.
 *
 * The build script rewrites `System.currentTimeMillis()` to `EvalClock.now()` in a temporary
 * copy of those sources, so sliding windows follow trace time and a replay gives the same
 * answer at any speed. That rewrite is the only change made to production code.
 */
object BuildConfig {
    const val DEBUG = false
}

object EvalClock {
    @JvmField
    @Volatile
    var nowMs: Long = 0L

    @JvmStatic
    fun now(): Long = nowMs
}
