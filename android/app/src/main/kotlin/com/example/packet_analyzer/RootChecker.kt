package com.example.packet_analyzer

import android.util.Log

/**
 * Single source of truth for root detection. Previously duplicated three ways
 * (MainActivity, NetHunterService, and a dead NativeInterface) with three
 * different, inconsistent heuristics — consolidated here.
 */
object RootChecker {
    private const val TAG = "RootChecker"

    /**
     * Root means su runs and returns uid 0. A su binary that is merely present, or a build
     * signed with test keys, proves nothing, and would select a capture path that cannot open
     * its socket.
     */
    fun isRooted(): Boolean = canExecuteSu()

    private fun canExecuteSu(): Boolean {
        return try {
            // Array form (not a single shell string) avoids quote-parsing ambiguity.
            val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            val rooted = exitCode == 0 && output.contains("uid=0")
            if (!rooted) Log.i(TAG, "su exited with $exitCode: ${output.take(200)}")
            rooted
        } catch (e: Exception) {
            // The usual answer on an unrooted device: there is no su to run
            Log.i(TAG, "su could not be started: ${e.message}")
            false
        }
    }
}
