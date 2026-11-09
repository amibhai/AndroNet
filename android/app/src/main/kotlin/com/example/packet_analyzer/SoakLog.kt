package com.example.packet_analyzer

import android.os.Environment
import android.util.Log
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter

/**
 * Evaluation builds only: what a long run on someone's own phone needs to report, and nothing else.
 * One line per alert, with its time, finding, severity and app. Addresses, names and payloads are
 * left out on purpose, so this file reveals which apps raised alerts and never what they talked to.
 */
object SoakLog {
    private const val TAG = "SoakLog"
    private const val FILE_NAME = "andronet_soak.tsv"

    private var writer: BufferedWriter? = null
    private val onAlert: (AnomalyDetector.Anomaly) -> Unit = ::record

    fun start() {
        if (writer != null) return
        try {
            val folder = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "AndroNet")
            folder.mkdirs()
            writer = BufferedWriter(FileWriter(File(folder, FILE_NAME), true))
            line("start", "", "", "")
            AnomalyDetector.addAnomalyListener(onAlert)
        } catch (e: Exception) {
            Log.e(TAG, "Could not open the soak log: ${e.message}")
        }
    }

    fun heartbeat(skippedPackets: Long, acceptedPackets: Long) {
        line("heartbeat", skippedPackets.toString(), acceptedPackets.toString(), "")
    }

    fun stop() {
        AnomalyDetector.removeAnomalyListener(onAlert)
        line("stop", "", "", "")
        try {
            writer?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Could not close the soak log: ${e.message}")
        }
        writer = null
    }

    private fun record(alert: AnomalyDetector.Anomaly) {
        val finding = alert.description.takeIf { it.startsWith("[") }?.substringBefore(']')?.drop(1) ?: alert.type.name
        line("alert", finding, alert.severity.name, alert.details["app"]?.toString() ?: "")
    }

    @Synchronized
    private fun line(kind: String, a: String, b: String, c: String) {
        try {
            writer?.run {
                write("${System.currentTimeMillis()}\t$kind\t$a\t$b\t$c\n")
                flush()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not write to the soak log: ${e.message}")
        }
    }
}
