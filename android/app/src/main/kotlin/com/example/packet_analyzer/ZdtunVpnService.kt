package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * VPN Service using zdtun for proper packet forwarding
 * Based on PCAPdroid's architecture
 */
class ZdtunVpnService : VpnService() {
    companion object {
        private const val TAG = "ZdtunVpnService"
        private const val TUN_BURST = 32
        // The wait also ends when a packet arrives, so this only sets how often an idle relay wakes
        private const val EVENT_WAIT_MS = 500
        // Traffic on the tunnel never leaves the phone, so its MTU is free to choose. zdtun hands
        // the client one segment per loop, so larger segments mean far fewer loops per megabyte.
        private const val TUN_MTU = 10000
        // A ConcurrentHashMap cannot hold null, so "looked up, no owner" needs its own value
        private const val OWNER_UNRESOLVED = ""
        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null
        private var anomalySink: EventChannel.EventSink? = null

        // Evaluation builds only: split the overhead of forwarding, analysis and the UI stream
        @Volatile var skipAnalysis = false
        @Volatile var skipUi = false
        @Volatile var soak = false
        private const val SOAK_HEARTBEAT_MS = 600_000L
        private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
        }

        fun setAnomalySink(sink: EventChannel.EventSink?) {
            anomalySink = sink
            Log.i(TAG, "Anomaly sink set: ${if (sink != null) "active" else "inactive"}")
        }

        fun sendAnomalyToFlutter(anomaly: Map<String, Any>) {
            mainHandler.post {
                try {
                    anomalySink?.success(anomaly)
                    Log.i(TAG, "🚨 Anomaly sent to Flutter: ${anomaly["type"]}")
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending anomaly to Flutter: ${e.message}")
                }
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunOutput: FileOutputStream? = null
    private var isRunning = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var zdtunInitialized = false
    private var refuseEncryptedDns = true
    private val analysisQueue = AnalysisQueue(::analyzeQueued, AnomalyDetector::reportAnalysisOverload)

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "ZdtunVpnService created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        Log.i(TAG, "ZdtunVpnService onStartCommand: action=$action")

        when (action) {
            "STOP_VPN" -> {
                Log.i(TAG, "Received STOP_VPN command")
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                if (!isRunning) {
                    Log.i(TAG, "Starting VPN service")
                    startVpnService()
                } else {
                    Log.i(TAG, "VPN already running")
                }
                return START_STICKY
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "andronet_capture",
                "AndroNet Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN packet capture service"
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "andronet_capture")
                .setContentTitle("AndroNet VPN Active")
                .setContentText("Capturing network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("AndroNet VPN Active")
                .setContentText("Capturing network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setOngoing(true)
                .build()
        }
    }

    private fun startVpnService() {
        // Must call startForeground() within 5 seconds on Android 8+ or the OS kills the service
        startForeground(1, buildNotification())

        try {
            // Establish VPN
            val builder = Builder()
                // IPv4 configuration
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)

                // IPv6 configuration - capture IPv6 traffic too
                .addAddress("fd00::2", 64)
                .addRoute("::", 0)

                // DNS servers (both IPv4 and IPv6)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addDnsServer("2001:4860:4860::8888")  // Google DNS IPv6
                .addDnsServer("2001:4860:4860::8844")  // Google DNS IPv6

                .setSession("Andronet VPN")
                .setMtu(TUN_MTU)
                .setBlocking(false)

            // Exclude this app from VPN to prevent capturing own traffic
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "✅ Excluded own app from VPN to prevent loops")
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude own app: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN")
                stopSelf()
                return
            }

            val tunFd = vpnInterface!!.fd
            Log.i(TAG, "VPN established with TUN fd: $tunFd")

            // Initialize zdtun
            if (!ZdtunVpn.nativeInit(this, tunFd, TUN_MTU)) {
                Log.e(TAG, "Failed to initialize zdtun")
                stopSelf()
                return
            }

            zdtunInitialized = true
            isRunning = true

            // Start PacketAnalysisManager for DPI and payload processing
            try {
                PacketAnalysisManager.getInstance().startAnalysis()
                Log.i(TAG, "✅ PacketAnalysisManager started")
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to start PacketAnalysisManager: ${e.message}")
            }
            AppContext.setBrowsers(findBrowsers())
            refuseEncryptedDns = !usesStrictPrivateDns()
            analysisQueue.start()
            if (BuildConfig.AUTOMATION && soak) {
                SoakLog.start()
                serviceScope.launch {
                    while (isRunning) {
                        SoakLog.heartbeat(analysisQueue.skippedPackets, analysisQueue.acceptedPackets)
                        delay(SOAK_HEARTBEAT_MS)
                    }
                }
            }

            // Register anomaly listener to send anomalies to Flutter
            AnomalyDetector.addAnomalyListener { anomaly ->
                val anomalyMap = mapOf(
                    "type" to anomaly.type.name,
                    "severity" to anomaly.severity.name,
                    "description" to anomaly.description,
                    "sourceIp" to (anomaly.sourceIp ?: ""),
                    "destinationIp" to (anomaly.destinationIp ?: ""),
                    "timestamp" to anomaly.timestamp,
                    "details" to anomaly.details
                )
                sendAnomalyToFlutter(anomalyMap)
            }
            Log.i(TAG, "✅ Anomaly listener registered")

            // Start packet processing
            serviceScope.launch {
                runCaptureLoop()
            }

            Log.i(TAG, "ZdtunVpnService started successfully")

        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Native library load failure: ${e.message}", e)
            mainHandler.post {
                methodChannel?.invokeMethod(
                    "onNativeLibraryError",
                    mapOf("error" to (e.message ?: "Native library failed to load"))
                )
            }
            stopSelf()
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error starting VPN: ${e.message}", e)
            mainHandler.post {
                methodChannel?.invokeMethod(
                    "onCaptureError",
                    mapOf("error" to (e.message ?: "Unknown error starting VPN"))
                )
            }
            stopSelf()
        }
    }

    /**
     * zdtun keeps one socket set and one reply buffer and is not thread-safe, so a single loop
     * owns it: it drains the TUN, then lets zdtun service its sockets. nativeHandleEvents also
     * waits on the TUN, so the loop sleeps only when neither side has anything to do.
     */
    private fun runCaptureLoop() {
        val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
        val buffer = ByteArray(32767) // Max IP packet size

        Log.i(TAG, "Started capture loop")

        try {
            while (isRunning) {
                var drained = 0
                while (drained < TUN_BURST) {
                    val length = inputStream.read(buffer)
                    if (length < 0) {
                        Log.w(TAG, "TUN read returned $length, stopping")
                        return
                    }
                    if (length == 0) break
                    handleTunPacket(buffer.copyOf(length))
                    drained++
                }
                // A full burst may have left more behind, so check the sockets without waiting
                ZdtunVpn.nativeHandleEvents(if (drained == TUN_BURST) 0 else EVENT_WAIT_MS)
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error in capture loop: ${e.message}", e)
            }
        } finally {
            Log.i(TAG, "Stopped capture loop")
        }
    }

    private fun handleTunPacket(packet: ByteArray) {
        if (refuseEncryptedDns && DnsVisibility.isEncryptedDns(packet)) return
        offerForAnalysis(packet, isOutgoing = true)
        ZdtunVpn.nativeHandlePacket(packet)
    }

    // The relay only hands packets over: record building, analysis and the UI run on the analysis
    // thread, so none of them can slow forwarding down.
    private fun offerForAnalysis(packet: ByteArray, isOutgoing: Boolean) {
        if (BuildConfig.AUTOMATION && skipAnalysis) return
        analysisQueue.offer(packet, isOutgoing, System.currentTimeMillis())
    }

    private fun analyzeQueued(item: AnalysisQueue.Item) {
        PacketClock.set(item.capturedAtMs)
        val packetInfo = parsePacket(item.packet, item.isOutgoing, item.capturedAtMs) ?: return
        sendPacketToFlutter(packetInfo, item.packet)
    }

    /**
     * Called from native code to send packet back to VPN
     * This is the remote2vpn callback
     */
    @Suppress("unused")
    fun sendPacketToVpn(packet: ByteArray) {
        try {
            val outputStream = tunOutput ?: FileOutputStream(vpnInterface!!.fileDescriptor).also { tunOutput = it }
            outputStream.write(packet)
            offerForAnalysis(packet, isOutgoing = false)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing to TUN: ${e.message}")
        }
    }

    // Automatic Private DNS falls back to plain DNS when refused. A chosen resolver does not: it would
    // leave the phone with no DNS at all, so that choice stands and names stay hidden from detection.
    private fun usesStrictPrivateDns(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val strict = cm.getLinkProperties(cm.activeNetwork)?.privateDnsServerName != null
            if (strict) Log.w(TAG, "Strict Private DNS is set, so DNS names stay hidden from detection")
            strict
        } catch (e: Exception) {
            Log.w(TAG, "Could not read the Private DNS setting: ${e.message}")
            false
        }
    }

    // The apps that claim any web link, which is what Android itself treats as a browser. The labels
    // must match resolveOwningApp's, which reads the application's label and not the activity's.
    private fun findBrowsers(): Set<String> = try {
        val webLink = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)
        packageManager.queryIntentActivities(webLink, android.content.pm.PackageManager.MATCH_ALL)
            .map { packageManager.getApplicationLabel(it.activityInfo.applicationInfo).toString() }
            .toSet()
    } catch (e: Exception) {
        Log.w(TAG, "Could not list browsers: ${e.message}")
        emptySet()
    }

    /**
     * Called from native code to protect sockets
     */
    @Suppress("unused")
    fun protectSocket(fd: Int): Boolean {
        val result = protect(fd)
        if (result) {
            Log.d(TAG, "✅ Socket protected: fd=$fd")
        } else {
            Log.w(TAG, "❌ Socket protection failed: fd=$fd")
        }
        return result
    }

    private fun parsePacket(packet: ByteArray, isOutgoing: Boolean, capturedAtMs: Long): Map<String, Any>? {
        return try {
            PacketRecord.fromIpPacket(packet, isOutgoing, PacketRecord.MODE_VPN, ::resolveOwningApp, capturedAtMs)
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing packet: ${e.message}")
            null
        }
    }

    // Cache of "protocol:localPort:remote" -> resolved app label. getConnectionOwnerUid()
    // is a Binder IPC call to netd — expensive to do on every single packet. A local
    // (ephemeral) port belongs to one app only for the lifetime of its socket and can
    // pass to another app after that, so the remote end is part of the key.
    private val owningAppCache = ConcurrentHashMap<String, String>()

    /**
     * Resolves the installed app that owns a given TCP/UDP flow, using
     * ConnectivityManager.getConnectionOwnerUid (API 29+) — something desktop
     * Wireshark has no equivalent of, since it isn't running on the device
     * whose traffic it's inspecting. Returns null on API < 29, for flows we
     * can't attribute (e.g. system/kernel traffic), or for our own traffic.
     */
    private fun resolveOwningApp(
        transportProtocol: Int,
        isOutgoing: Boolean,
        sourceIP: String,
        sourcePort: Int,
        destIP: String,
        destPort: Int
    ): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        if (sourcePort <= 0 || destPort <= 0) return null

        val localPort = if (isOutgoing) sourcePort else destPort
        val cacheKey = "$transportProtocol:$localPort:" + if (isOutgoing) "$destIP:$destPort" else "$sourceIP:$sourcePort"
        owningAppCache[cacheKey]?.let { return if (it == OWNER_UNRESOLVED) null else it }
        if (owningAppCache.size > 1000) owningAppCache.clear()

        val resolved = try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (cm == null) {
                null
            } else {
                val local = if (isOutgoing) InetSocketAddress(sourceIP, sourcePort) else InetSocketAddress(destIP, destPort)
                val remote = if (isOutgoing) InetSocketAddress(destIP, destPort) else InetSocketAddress(sourceIP, sourcePort)
                val uid = cm.getConnectionOwnerUid(transportProtocol, local, remote)
                val packageName = if (uid <= 0 || uid == Process.myUid()) {
                    null
                } else {
                    packageManager.getPackagesForUid(uid)?.firstOrNull()
                }
                if (packageName == null) {
                    null
                } else {
                    val appInfo = packageManager.getApplicationInfo(packageName, 0)
                    packageManager.getApplicationLabel(appInfo).toString()
                }
            }
        } catch (e: Exception) {
            null
        }

        owningAppCache[cacheKey] = resolved ?: OWNER_UNRESOLVED
        return resolved
    }

    private fun sendPacketToFlutter(packetInfo: Map<String, Any>, rawPacket: ByteArray? = null) {
        try {
            // Phase 2: Process packet through PacketAnalysisManager
            val enrichedPacket = try {
                PacketAnalysisManager.getInstance().processPacket(packetInfo, rawPacket)
            } catch (e: Exception) {
                Log.w(TAG, "PacketAnalysisManager not available: ${e.message}")
                packetInfo
            }
            if (BuildConfig.AUTOMATION && skipUi) return

            UiStream.offer(packetSink, enrichedPacket)
        } catch (e: Exception) {
            Log.e(TAG, "Error posting to main thread: ${e.message}")
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by system")
        try {
            isRunning = false
            serviceScope.cancel()
            analysisQueue.stop()
            if (zdtunInitialized) {
                ZdtunVpn.nativeCleanup()
                zdtunInitialized = false
            }
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(true)
        } catch (e: Exception) {
            Log.e(TAG, "Error during revoke cleanup: ${e.message}", e)
        }
        super.onRevoke()
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
        Log.i(TAG, "Stopping ZdtunVpnService")
        isRunning = false

        // Whatever is still queued has to reach the export before it is finalized
        analysisQueue.stop()
        if (BuildConfig.AUTOMATION && soak) SoakLog.stop()

        // Stop PacketAnalysisManager (internally calls finalizePcap)
        try {
            PacketAnalysisManager.getInstance().stopAnalysis()
            Log.i(TAG, "PacketAnalysisManager stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping PacketAnalysisManager: ${e.message}")
        }

        serviceScope.cancel()

        if (zdtunInitialized) {
            ZdtunVpn.nativeCleanup()
            zdtunInitialized = false
        }

        vpnInterface?.close()
        vpnInterface = null

        super.onDestroy()
        Log.i(TAG, "ZdtunVpnService stopped")
    }
}
