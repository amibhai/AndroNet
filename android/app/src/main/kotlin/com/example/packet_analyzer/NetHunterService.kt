package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.Process
import android.util.Log
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.util.zip.ZipFile

/**
 * Root capture service.
 *
 * An app process cannot open a packet socket even on a rooted device, because root belongs to
 * the processes su starts. So this service starts jni/capture_helper.c through su and reads
 * frames from its stdout. From there on a frame takes the same path as a VPN-mode packet:
 * PacketRecord, PacketAnalysisManager.processPacket, then the shared Flutter sink.
 */
class NetHunterService : Service() {

    private val TAG = "NetHunterService"
    @Volatile private var isCapturing = false
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private var networkInterface = "any" // Default to capture on all interfaces
    private var helper: java.lang.Process? = null
    private var readerThread: Thread? = null

    companion object {
        private const val HELPER_ENTRY = "libcapd.so"
        private const val MAX_FRAME = 65536
        private const val ETHERTYPE_IPV4 = 0x0800
        private const val ETHERTYPE_IPV6 = 0x86DD
        private const val ETHERTYPE_ARP = 0x0806
        private const val PACKET_OUTGOING = 4
        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
        }
    }

    override fun onBind(intent: Intent): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "🚀 NetHunter Service created (root capture)")
        createNotificationChannel()
    }

    private fun isRooted(): Boolean = RootChecker.isRooted()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        when (action) {
            "START_CAPTURE" -> {
                // Must call startForeground() within 5 seconds on Android 8+ or the OS kills the service
                startForeground()
                if (!isRooted()) {
                    Log.w(TAG, "Root not available — root capture unavailable")
                    onStatusUpdate("Root capture requires root. Use VPN mode instead.")
                    stopSelf()
                    return START_NOT_STICKY
                }
                val iface = intent.getStringExtra("interface") ?: "any"
                startRootCapture(iface)
            }
            "STOP_CAPTURE" -> {
                stopRootCapture()
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "libpcap_channel",
                "Root Packet Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Interface-level packet capture"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun startForeground() {
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "libpcap_channel")
                .setContentTitle("Root Capture Active")
                .setContentText("Capturing packets on $networkInterface")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Root Capture Active")
                .setContentText("Capturing packets on $networkInterface")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        }

        startForeground(2, notification)
    }

    /**
     * The helper ships as a native library so the build compiles it for each ABI, but the
     * app is packaged with useLegacyPackaging = false, which leaves libraries inside the APK,
     * so it has to be copied out to somewhere it can be executed from.
     */
    private fun installHelper(): File {
        val target = File(filesDir, "capd")
        // Written beside the target and renamed over it: a helper from an earlier session may
        // still be on its way out, and a running binary cannot be opened for writing (ETXTBSY).
        val staging = File(filesDir, "capd.tmp")
        for (abi in Build.SUPPORTED_ABIS) {
            ZipFile(applicationInfo.sourceDir).use { apk ->
                val entry = apk.getEntry("lib/$abi/$HELPER_ENTRY") ?: return@use
                apk.getInputStream(entry).use { input ->
                    staging.outputStream().use { input.copyTo(it) }
                }
                staging.setExecutable(true, true)
                if (!staging.renameTo(target)) throw IllegalStateException("Could not install $target")
                return target
            }
        }
        throw IllegalStateException("$HELPER_ENTRY is missing from the APK")
    }

    private fun startRootCapture(interfaceName: String) {
        if (isCapturing) {
            Log.w(TAG, "Capture already running")
            return
        }

        Log.i(TAG, "🔍 Starting root capture on: $interfaceName")
        networkInterface = interfaceName

        try {
            val binary = installHelper()
            val command = "${binary.absolutePath} --iface $interfaceName --uid ${Process.myUid()}"
            val process = ProcessBuilder("su", "-c", command).start()
            helper = process
            isCapturing = true

            PacketAnalysisManager.getInstance().startAnalysis()

            readerThread = Thread({ readFrames(process) }, "root-capture-reader").apply {
                isDaemon = true
                start()
            }
            Thread({
                val errors = process.errorStream.bufferedReader().readText()
                if (errors.isNotBlank()) {
                    Log.e(TAG, "Capture helper: $errors")
                    onStatusUpdate("Capture helper failed: ${errors.trim()}")
                }
            }, "root-capture-stderr").apply {
                isDaemon = true
                start()
            }

            Log.i(TAG, "✅ Root capture started")
            onStatusUpdate("Root capture started on $interfaceName")
        } catch (e: Exception) {
            isCapturing = false
            Log.e(TAG, "❌ Root capture error: ${e.message}", e)
            onStatusUpdate("Error: ${e.message}")
        }
    }

    private fun readFrames(process: java.lang.Process) {
        try {
            val input = DataInputStream(BufferedInputStream(process.inputStream, 1 shl 16))
            while (isCapturing) {
                val length = input.readInt()
                val ethertype = input.readUnsignedShort()
                val packetType = input.readUnsignedByte()
                input.readUnsignedByte()
                if (length <= 0 || length > MAX_FRAME) {
                    Log.e(TAG, "Bad frame length $length; stopping")
                    return
                }
                val frame = ByteArray(length)
                input.readFully(frame)
                handleFrame(ethertype, packetType == PACKET_OUTGOING, frame)
            }
        } catch (e: EOFException) {
            Log.i(TAG, "Capture helper closed its stream")
        } catch (e: Exception) {
            if (isCapturing) Log.e(TAG, "Error reading frames: ${e.message}", e)
        }
    }

    private fun handleFrame(ethertype: Int, isOutgoing: Boolean, frame: ByteArray) {
        val manager = PacketAnalysisManager.getInstance()
        val enriched = when (ethertype) {
            ETHERTYPE_IPV4, ETHERTYPE_IPV6 -> {
                val record = PacketRecord.fromIpPacket(frame, isOutgoing, PacketRecord.MODE_ROOT) ?: return
                manager.processPacket(record, frame)
            }
            ETHERTYPE_ARP -> {
                val record = parseArp(frame, isOutgoing) ?: return
                manager.processPacket(record, null)
            }
            else -> return
        }
        UiStream.offer(packetSink, enriched)
    }

    /** Ethernet/IPv4 ARP body: hw(2) proto(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4). */
    private fun parseArp(frame: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
        if (frame.size < 28) return null
        val isEthernetIpv4 = frame[0].toInt() == 0 && frame[1].toInt() == 1 &&
                frame[2].toInt() == 0x08 && frame[3].toInt() == 0x00
        if (!isEthernetIpv4) return null
        val mac = (8 until 14).joinToString(":") { "%02x".format(frame[it]) }
        val senderIp = (14 until 18).joinToString(".") { (frame[it].toInt() and 0xFF).toString() }
        val targetIp = (24 until 28).joinToString(".") { (frame[it].toInt() and 0xFF).toString() }
        return PacketRecord.fromArp(mac, senderIp, targetIp, frame.size, isOutgoing, PacketRecord.MODE_ROOT)
    }

    private fun stopRootCapture() {
        if (!isCapturing) {
            Log.w(TAG, "Capture not running")
            return
        }

        Log.i(TAG, "🛑 Stopping root capture")

        isCapturing = false
        // Closing the pipe ends the helper: its next write fails and it exits as root's last act
        helper?.destroy()
        helper = null

        try {
            PacketAnalysisManager.getInstance().stopAnalysis()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping analysis: ${e.message}", e)
        }

        stopForeground(true)
        Log.i(TAG, "✅ Root capture stopped")
        onStatusUpdate("Capture stopped")
    }

    /**
     * Status updates for the Flutter UI
     */
    private fun onStatusUpdate(status: String) {
        Log.i(TAG, "Status: $status")
        mainHandler.post {
            methodChannel?.invokeMethod("onLibpcapStatus", mapOf("status" to status))
        }
    }

    // Commit 13 — app swiped from recents while service is running
    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(TAG, "Task removed — finalizing PCAP before death")
        try {
            PacketAnalysisManager.getInstance().finalizePcap()
        } catch (e: Exception) {
            Log.e(TAG, "Error finalizing PCAP on task removal: ${e.message}")
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "NetHunter Service destroyed")
        if (isCapturing) stopRootCapture()
    }
}
