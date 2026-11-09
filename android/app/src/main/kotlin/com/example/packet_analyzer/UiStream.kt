package com.example.packet_analyzer

import android.os.Handler
import android.os.Looper
import android.util.Log
import io.flutter.plugin.common.EventChannel
import java.util.concurrent.atomic.AtomicInteger

/**
 * Best-effort packet stream to the Flutter UI. The capture loop can outrun the main thread by
 * an order of magnitude, and an unbounded Handler queue of decoded packets ends with the OS
 * killing the process. So the UI is shown what it can keep up with. Analysis and PCAP export run
 * before this point and always see every packet.
 */
object UiStream {
    private const val TAG = "UiStream"
    private const val MAX_PENDING = 256

    private val handler = Handler(Looper.getMainLooper())
    private val pending = AtomicInteger(0)

    fun offer(sink: EventChannel.EventSink?, packet: Map<String, Any>) {
        if (sink == null || pending.get() >= MAX_PENDING) return
        pending.incrementAndGet()
        handler.post {
            try {
                sink.success(packet)
            } catch (e: Exception) {
                Log.e(TAG, "Error in EventSink: ${e.message}")
            } finally {
                pending.decrementAndGet()
            }
        }
    }
}
