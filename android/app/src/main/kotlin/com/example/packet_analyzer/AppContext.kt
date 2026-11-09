package com.example.packet_analyzer

/**
 * What only the device can know about a packet: which app sent it. A network sensor sees addresses,
 * and on the VPN path every outgoing packet has the same source address, so the app is the unit that
 * detection should count by. The rooted path has no app identity and falls back to the source address.
 */
object AppContext {
    // A page load legitimately fans out to many hosts at once. An app that is not a browser has no
    // such excuse, so it keeps the stricter limit. Calibrated on measured browsing.
    private const val BROWSER_LIMIT_FACTOR = 3.0

    @Volatile private var browsers: Set<String> = emptySet()

    // Evaluation builds can run without app identity, to measure what it adds on the same traffic
    @Volatile var identityEnabled = true

    fun setBrowsers(labels: Set<String>) {
        browsers = labels
    }

    fun app(packetInfo: Map<String, Any>): String =
        if (identityEnabled) packetInfo["owningApp"] as? String ?: "" else ""

    /** Who a rate window or a profile belongs to: the app where known, else the source address. */
    fun principal(packetInfo: Map<String, Any>): String =
        app(packetInfo).ifEmpty { packetInfo["sourceIp"] as? String ?: "" }

    fun limitFactor(packetInfo: Map<String, Any>): Double =
        if (app(packetInfo) in browsers) BROWSER_LIMIT_FACTOR else 1.0
}

/**
 * The TLS libraries each app has been seen to use, known by their cipher lists. An app settles on a few,
 * so a new one from a settled app means it started talking through different code: a loaded plugin, or
 * an implant.
 * Bounded, and kept across sessions so that profiles survive restarts.
 */
object AppProfiles {
    private const val MAX_APPS = 256
    private const val MAX_LIBRARIES = 16
    private const val SETTLED_AFTER_HELLOS = 20

    private class Profile {
        val libraries = LinkedHashSet<String>()
        var sinceNew = 0
    }

    private val profiles = object : LinkedHashMap<String, Profile>(32, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Profile>?) = size > MAX_APPS
    }

    /** True when [app], whose TLS use had settled, just presented a cipher list new to it. */
    @Synchronized
    fun observeHello(app: String, cipherList: String): Boolean {
        val profile = profiles.getOrPut(app) { Profile() }
        if (cipherList in profile.libraries) {
            profile.sinceNew++
            return false
        }
        val settled = profile.sinceNew >= SETTLED_AFTER_HELLOS
        if (profile.libraries.size < MAX_LIBRARIES) profile.libraries.add(cipherList)
        profile.sinceNew = 0
        return settled
    }

    /** One line per app: its name, hellos since its last new library, then the libraries. */
    @Synchronized
    fun dump(): String = profiles.entries.joinToString("\n") { (app, profile) ->
        (listOf(app, profile.sinceNew.toString()) + profile.libraries).joinToString("\t")
    }

    @Synchronized
    fun load(text: String) {
        for (line in text.lineSequence()) {
            val fields = line.split('\t')
            if (fields.size < 3) continue
            val profile = Profile()
            profile.sinceNew = fields[1].toIntOrNull() ?: 0
            profile.libraries.addAll(fields.drop(2).take(MAX_LIBRARIES))
            profiles[fields[0]] = profile
        }
    }

    @Synchronized
    fun reset() {
        profiles.clear()
    }
}
