package com.example.packet_analyzer

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Random

class FlowDetectorsTest {
    private val alerts = mutableListOf<AnomalyDetector.Anomaly>()
    private val listener: (AnomalyDetector.Anomaly) -> Unit = { alerts.add(it) }

    @Before
    fun setUp() {
        PacketClock.reset()
        AnomalyDetector.reset()
        AnomalyDetector.adaptiveThresholds.reset()
        AppProfiles.reset()
        DomainTracker.clear()
        AppContext.setBrowsers(emptySet())
        RuleEngine.clearState()
        AnomalyDetector.removeAnomalyListener(listener)
        AnomalyDetector.addAnomalyListener(listener)
        alerts.clear()
    }

    @After
    fun tearDown() {
        PacketClock.reset()
        AppContext.setBrowsers(emptySet())
        AppContext.identityEnabled = true
    }

    private fun fired(id: String) = alerts.any { it.description.startsWith("[$id]") }
    private fun fired(type: AnomalyDetector.AnomalyType) = alerts.any { it.type == type }
    private fun random(size: Int, seed: Long = 7) = ByteArray(size).also { Random(seed).nextBytes(it) }

    private fun tcpPacket(srcPort: Int, dstPort: Int, flags: Int, payload: ByteArray = ByteArray(0), srcIp: String = "192.0.2.10", dstIp: String = "198.51.100.20"): ByteArray {
        val total = 40 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = total.toByte()
        p[8] = 64
        p[9] = 6
        ip(srcIp).copyInto(p, 12)
        ip(dstIp).copyInto(p, 16)
        p[20] = (srcPort shr 8).toByte()
        p[21] = srcPort.toByte()
        p[22] = (dstPort shr 8).toByte()
        p[23] = dstPort.toByte()
        p[32] = 0x50
        p[33] = flags.toByte()
        payload.copyInto(p, 40)
        return p
    }

    private fun icmpPacket(srcIp: String, dstIp: String, type: Int = 8, payload: ByteArray = ByteArray(56)): ByteArray {
        val total = 28 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = total.toByte()
        p[8] = 64
        p[9] = 1
        ip(srcIp).copyInto(p, 12)
        ip(dstIp).copyInto(p, 16)
        p[20] = type.toByte()
        payload.copyInto(p, 28)
        return p
    }

    private fun ip(text: String) = text.split('.').map { it.toInt().toByte() }.toByteArray()

    private fun run(packet: ByteArray, outgoing: Boolean = true, app: String? = null) {
        val resolver = app?.let { name -> PacketRecord.OwningAppResolver { _, _, _, _, _, _ -> name } }
        val record = PacketRecord.fromIpPacket(packet, outgoing, PacketRecord.MODE_VPN, resolver)!!
        val (enriched, payload) = PacketPipeline.dissectAndEnrich(record, packet)
        PacketPipeline.analyze(enriched, payload)
    }

    private val psh = 0x18
    private val syn = 0x02

    private fun start(srcPort: Int, dstPort: Int, app: String? = null) = run(tcpPacket(srcPort, dstPort, syn), app = app)

    // === The opaque-flow test, on what real protocols open with ===

    @Test
    fun `random bytes look opaque`() {
        assertTrue(FlowDetectors.isOpaque(random(200)))
    }

    @Test
    fun `text, sparse binary, TLS and HTTP do not look opaque`() {
        assertFalse(FlowDetectors.isOpaque("SSH-2.0-OpenSSH_9.6 and some more readable text".toByteArray()))
        assertFalse(FlowDetectors.isOpaque(ByteArray(200)))
        assertFalse(FlowDetectors.isOpaque(byteArrayOf(0x16, 3, 1, 2, 0) + random(300)))
        assertFalse(FlowDetectors.isOpaque("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()))
    }

    @Test
    fun `short payloads carry too little evidence`() {
        assertFalse(FlowDetectors.isOpaque(random(8)))
    }

    @Test
    fun `an opaque first payload on an unusual port raises an alert`() {
        start(50000, 4444)
        run(tcpPacket(50000, 4444, psh, random(300)))
        assertTrue(fired("FLOW-001"))
    }

    @Test
    fun `a flow whose start was not seen is not judged by what it sends next`() {
        run(tcpPacket(50000, 4444, psh, random(300)))
        assertFalse(fired("FLOW-001"))
        run(tcpPacket(80, 50001, psh, random(300)), outgoing = false)
        assertFalse(fired("FLOW-002"))
    }

    @Test
    fun `only a flow's first payload is tested`() {
        start(50000, 4444)
        run(tcpPacket(50000, 4444, psh, "hello there, this is readable text and plenty of it".toByteArray()))
        run(tcpPacket(50000, 4444, psh, random(300)))
        assertFalse(fired("FLOW-001"))
    }

    @Test
    fun `encrypted ports are expected to look opaque`() {
        start(50000, 443)
        run(tcpPacket(50000, 443, psh, random(300)))
        assertFalse(fired("FLOW-001"))
    }

    @Test
    fun `messengers run their own encrypted protocols on the XMPP port`() {
        start(50000, 5222, app = "Messenger")
        run(tcpPacket(50000, 5222, psh, random(300)), app = "Messenger")
        assertFalse(fired("FLOW-001"))
    }

    private fun failedLookup(name: String) = FlowDetectors.inspect(
        mapOf(
            "protocol" to "UDP", "direction" to "incoming", "sourceIp" to "198.51.100.53", "destinationIp" to "192.0.2.10",
            "sourcePort" to 53, "destinationPort" to 50000, "owningApp" to "Game",
            "dnsData" to mapOf("type" to "Response", "queryName" to name, "responseCode" to "Name Error (3)")
        ),
        null
    ) { alerts.add(it) }

    @Test
    fun `domain generation tries many names, where a retried name is one failure`() {
        PacketClock.set(1_000_000L)
        repeat(100) { failedLookup("z.adserver.example") }
        assertFalse(fired("FLOW-005"))

        repeat(25) { i -> failedLookup("x$i.generated.example") }
        assertTrue(fired("FLOW-005"))
    }

    @Test
    fun `an app reopening opaque flows on one port is reported once an hour`() {
        fun opaqueFlow(srcPort: Int, dstPort: Int, atMs: Long) {
            PacketClock.set(atMs)
            start(srcPort, dstPort, app = "Game")
            run(tcpPacket(srcPort, dstPort, psh, random(300)), app = "Game")
        }
        fun reports() = alerts.count { it.description.startsWith("[FLOW-001]") }

        opaqueFlow(50000, 4444, 1_000_000L)
        opaqueFlow(50001, 4444, 1_060_000L)
        opaqueFlow(50002, 4444, 1_120_000L)
        assertEquals(1, reports())

        opaqueFlow(50003, 4445, 1_180_000L)
        assertEquals("another port is another finding", 2, reports())

        opaqueFlow(50004, 4444, 4_700_000L)
        assertEquals("and the same one is reported again after an hour", 3, reports())
    }

    @Test
    fun `an ICMP error quoting ciphertext is no covert channel, and an echo carrying it is`() {
        repeat(10) { run(icmpPacket("192.0.2.10", "198.51.100.20", type = 3, payload = random(300))) }
        assertFalse(fired(AnomalyDetector.AnomalyType.COVERT_CHANNEL))

        repeat(10) { i -> run(icmpPacket("192.0.2.10", "198.51.100.20", type = 8, payload = random(300, seed = i.toLong()))) }
        assertTrue(fired(AnomalyDetector.AnomalyType.COVERT_CHANNEL))
    }

    @Test
    fun `frame padding is not payload`() {
        // An empty SYN/ACK padded to a minimum Ethernet frame by the sending interface
        val padded = tcpPacket(80, 2944, 0x12, srcIp = "198.51.100.20", dstIp = "192.0.2.10").copyOf(60)
        padded[3] = 40
        padded[40] = 0x42
        start(2944, 80)
        run(padded, outgoing = false)
        assertFalse(fired("FLOW-002"))
    }

    // === Does a well-known port speak its protocol ===

    @Test
    fun `a shell on the DNS port is a mismatch`() {
        start(1396, 53)
        run(tcpPacket(53, 1396, psh, "Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright".toByteArray(), srcIp = "198.51.100.20", dstIp = "192.0.2.10"), outgoing = false)
        assertTrue(fired("FLOW-002"))
    }

    @Test
    fun `real TCP DNS is no mismatch`() {
        val query = byteArrayOf(0, 29, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + ByteArray(17)
        assertEquals(true, FlowDetectors.speaksPortProtocol(53, query))
        start(50000, 53)
        run(tcpPacket(50000, 53, psh, query))
        assertFalse(fired("FLOW-002"))
    }

    @Test
    fun `web and SSH ports accept their own protocols only`() {
        assertEquals(true, FlowDetectors.speaksPortProtocol(80, "GET / HTTP/1.1\r\n\r\n".toByteArray()))
        assertEquals(false, FlowDetectors.speaksPortProtocol(80, random(100)))
        assertEquals(true, FlowDetectors.speaksPortProtocol(22, "SSH-2.0-x\r\n".toByteArray()))
        assertEquals(false, FlowDetectors.speaksPortProtocol(22, "hello".toByteArray()))
        assertNull(FlowDetectors.speaksPortProtocol(4444, random(100)))
    }

    // === Beaconing ===

    private fun beacon(gapMs: (Int) -> Long, count: Int = 14, app: String? = "Flashlight") {
        var t = 1_000_000L
        repeat(count) { i ->
            PacketClock.set(t)
            run(tcpPacket(50000, 8443, psh, "ping".toByteArray()), app = app)
            t += gapMs(i)
        }
    }

    @Test
    fun `check-ins on a timer to a bare address are beaconing`() {
        beacon({ 30_000L })
        assertTrue(fired("FLOW-003"))
    }

    @Test
    fun `small jitter does not hide a beacon`() {
        val jitter = Random(3)
        beacon({ 30_000L + jitter.nextInt(3000) })
        assertTrue(fired("FLOW-003"))
    }

    @Test
    fun `one long pause does not hide a beacon`() {
        beacon({ if (it == 3) 400_000L else 30_000L })
        assertTrue(fired("FLOW-003"))
    }

    @Test
    fun `irregular traffic is no beacon`() {
        val gaps = longArrayOf(2_000, 90_000, 4_000, 250_000, 8_000, 30_000, 1_500, 120_000, 60_000, 3_000, 400_000, 7_000, 5_000, 100_000)
        beacon({ gaps[it] })
        assertFalse(fired("FLOW-003"))
    }

    @Test
    fun `one destination is reported once an hour, however long it goes on`() {
        beacon({ 30_000L }, count = 40)
        assertEquals(1, alerts.count { it.description.startsWith("[FLOW-003]") })
    }

    @Test
    fun `a destination reached through a DNS name is not called a beacon`() {
        DomainTracker.clear()
        DomainTracker.recordDnsResolution("push.example.com", "198.51.100.20")
        beacon({ 30_000L })
        assertFalse(fired("FLOW-003"))
        DomainTracker.clear()
    }

    @Test
    fun `a connection keeps its name after the DNS entry for it expires`() {
        DomainTracker.clear()
        PacketClock.set(1_000_000L)
        DomainTracker.recordDnsResolution("push.example.com", "198.51.100.20")
        beacon({ 60_000L }, count = 20)
        assertFalse(fired("FLOW-003"))
        DomainTracker.clear()
    }

    // === DNS ===

    private fun dnsQuery(name: String): ByteArray {
        val question = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }.toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
        val dns = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) + question
        val total = 28 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = total.toByte()
        p[9] = 17
        ip("192.0.2.10").copyInto(p, 12)
        ip("192.0.2.53").copyInto(p, 16)
        p[20] = (40000 shr 8).toByte()
        p[21] = 40000.toByte()
        p[23] = 53
        dns.copyInto(p, 28)
        return p
    }

    @Test
    fun `a few long names are not a tunnel, and many under one zone are`() {
        PacketClock.set(1_000_000L)
        repeat(9) { i -> run(dnsQuery("3e47087e533333024ab95f932277b94$i.safeframe.googlesyndication.com")) }
        assertFalse(fired(AnomalyDetector.AnomalyType.DNS_TUNNELING))
        run(dnsQuery("3e47087e533333024ab95f932277b94x.safeframe.googlesyndication.com"))
        assertTrue(fired(AnomalyDetector.AnomalyType.DNS_TUNNELING))
    }

    @Test
    fun `long names spread over zones are not a tunnel`() {
        PacketClock.set(1_000_000L)
        repeat(30) { i -> run(dnsQuery("3e47087e533333024ab95f932277b94a7.safeframe.example$i.com")) }
        assertFalse(alerts.any { it.description.startsWith("Many long DNS names") })
    }

    // === Floods that per-source counting cannot see ===

    @Test
    fun `a spoofed flood is seen at its target`() {
        PacketClock.set(1_000_000L)
        repeat(400) { i -> run(icmpPacket("10.${i / 250}.${i % 250}.7", "198.51.100.20")) }
        assertTrue(fired(AnomalyDetector.AnomalyType.DISTRIBUTED_FLOOD))
    }

    @Test
    fun `one chatty source is not a distributed flood`() {
        PacketClock.set(1_000_000L)
        repeat(400) { run(icmpPacket("10.0.0.7", "198.51.100.20")) }
        assertFalse(fired(AnomalyDetector.AnomalyType.DISTRIBUTED_FLOOD))
    }

    @Test
    fun `many clients spread over time are not a flood`() {
        repeat(400) { i ->
            PacketClock.set(1_000_000L + i * 100L)
            run(icmpPacket("10.${i / 250}.${i % 250}.7", "198.51.100.20"))
        }
        assertFalse(fired(AnomalyDetector.AnomalyType.DISTRIBUTED_FLOOD))
    }

    // === ARP ===

    private fun arp(mac: String, ip: String) {
        val record = PacketRecord.fromArp(mac, ip, "172.16.0.107", 60, false, PacketRecord.MODE_ROOT)
        val (enriched, payload) = PacketPipeline.dissectAndEnrich(record, null)
        PacketPipeline.analyze(enriched, payload)
    }

    @Test
    fun `one MAC claiming two addresses is flagged with no binding ever changing`() {
        arp("00:25:b3:bf:91:ee", "172.16.0.1")
        assertFalse(fired(AnomalyDetector.AnomalyType.ARP_SPOOFING))
        arp("00:25:b3:bf:91:ee", "172.16.0.105")
        assertTrue(fired(AnomalyDetector.AnomalyType.ARP_SPOOFING))
    }

    @Test
    fun `address probes do not count as a claim`() {
        arp("00:25:b3:bf:91:ee", "0.0.0.0")
        arp("00:25:b3:bf:91:ee", "172.16.0.5")
        assertFalse(fired(AnomalyDetector.AnomalyType.ARP_SPOOFING))
    }

    // === Patterns split across segments ===

    @Test
    fun `a signature split across two segments still matches`() {
        run(tcpPacket(50000, 9000, psh, ("x".repeat(40) + "std").toByteArray()))
        assertFalse(fired("MAL-001"))
        run(tcpPacket(50000, 9000, psh, ("api_sys_process_execute" + "y".repeat(40)).toByteArray()))
        assertTrue(fired("MAL-001"))
    }

    // === App context ===

    @Test
    fun `apps are counted apart, though they share one source address`() {
        PacketClock.set(1_000_000L)
        repeat(70) { i -> run(tcpPacket(40000 + i, 443, syn, dstIp = "198.51.100.${i + 1}"), app = "App A") }
        repeat(70) { i -> run(tcpPacket(41000 + i, 443, syn, dstIp = "198.51.100.${i + 1}"), app = "App B") }
        assertFalse(fired(AnomalyDetector.AnomalyType.CONNECTION_FLOOD))

        repeat(110) { i -> run(tcpPacket(42000 + i, 443, syn, dstIp = "198.51.100.${i + 1}"), app = "App C") }
        assertTrue(fired(AnomalyDetector.AnomalyType.CONNECTION_FLOOD))
    }

    @Test
    fun `a browser may open more connections than other apps`() {
        AppContext.setBrowsers(setOf("Chrome"))
        PacketClock.set(1_000_000L)
        repeat(250) { i -> run(tcpPacket(40000 + i, 443, syn, dstIp = "198.51.${100 + i / 200}.${i % 200 + 1}"), app = "Chrome") }
        assertFalse(fired(AnomalyDetector.AnomalyType.CONNECTION_FLOOD))
    }

    @Test
    fun `an alert names the app that caused it`() {
        start(50000, 4444, app = "Flashlight")
        run(tcpPacket(50000, 4444, psh, random(300)), app = "Flashlight")
        val alert = alerts.single { it.description.startsWith("[FLOW-001]") }
        assertTrue(alert.description.contains("Flashlight"))
        assertEquals("Flashlight", alert.details["app"])
    }

    @Test
    fun `an evaluation run can turn app identity off`() {
        AppContext.identityEnabled = false
        start(50000, 4444, app = "Game")
        run(tcpPacket(50000, 4444, psh, random(300)), app = "Game")
        assertFalse(alerts.single { it.description.startsWith("[FLOW-001]") }.description.contains("Game"))
    }

    @Test
    fun `without app identity detection falls back to the source address`() {
        PacketClock.set(1_000_000L)
        repeat(110) { i -> run(tcpPacket(42000 + i, 443, syn, dstIp = "198.51.100.${i + 1}")) }
        assertTrue(fired(AnomalyDetector.AnomalyType.CONNECTION_FLOOD))
    }

    // === Per-app TLS profiles ===

    @Test
    fun `a settled app presenting a new TLS library is flagged once`() {
        repeat(25) { assertFalse(AppProfiles.observeHello("Maps", "t13d1516h2_aaa_bbb")) }
        assertTrue(AppProfiles.observeHello("Maps", "t13d0000h2_new_new"))
        assertFalse(AppProfiles.observeHello("Maps", "t13d0000h2_new_new"))
    }

    @Test
    fun `an app changing ALPN or its server name keeps its TLS library`() {
        fun hello(srcPort: Int, payload: ByteArray) {
            start(srcPort, 443, app = "Maps")
            run(tcpPacket(srcPort, 443, psh, payload), app = "Maps")
        }
        repeat(25) { i -> hello(50000 + i, clientHello()) }

        hello(50100, clientHello(alpn = null))
        hello(50101, clientHello(sni = null, alpn = "http/1.1"))
        assertFalse(fired("APP-001"))

        hello(50102, clientHello(cipherList = listOf(0xc030, 0xc02f)))
        assertTrue(fired("APP-001"))
    }

    @Test
    fun `an app still settling may add fingerprints freely`() {
        assertFalse(AppProfiles.observeHello("Maps", "a"))
        assertFalse(AppProfiles.observeHello("Maps", "b"))
        repeat(5) { assertFalse(AppProfiles.observeHello("Maps", "a")) }
        assertFalse(AppProfiles.observeHello("Maps", "c"))
    }

    @Test
    fun `profiles survive a restart`() {
        repeat(25) { AppProfiles.observeHello("Maps", "a") }
        val saved = AppProfiles.dump()
        AppProfiles.reset()
        DomainTracker.clear()
        AppProfiles.load(saved)
        assertTrue(AppProfiles.observeHello("Maps", "b"))
    }

    // === TLS fingerprints ===

    private fun clientHello(sni: String? = "example.com", alpn: String? = "h2", cipherList: List<Int> = listOf(0x1301, 0x1302, 0xc02f)): ByteArray {
        fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
        fun ext(type: Int, data: ByteArray) = u16(type) + u16(data.size) + data
        val ciphers = cipherList.fold(u16(0x0a0a)) { bytes, cipher -> bytes + u16(cipher) }
        var extensions = ext(0x2a2a, ByteArray(0))
        if (sni != null) {
            val name = sni.toByteArray()
            extensions += ext(0, u16(name.size + 3) + byteArrayOf(0) + u16(name.size) + name)
        }
        extensions += ext(10, u16(4) + u16(0x001d) + u16(0x0017))
        extensions += ext(11, byteArrayOf(1, 0))
        extensions += ext(13, u16(4) + u16(0x0403) + u16(0x0804))
        if (alpn != null) {
            val value = alpn.toByteArray()
            extensions += ext(16, u16(value.size + 1) + byteArrayOf(value.size.toByte()) + value)
        }
        extensions += ext(43, byteArrayOf(4) + u16(0x0304) + u16(0x0303))
        val body = u16(0x0303) + ByteArray(32) + byteArrayOf(0) + u16(ciphers.size) + ciphers + byteArrayOf(1, 0) + u16(extensions.size) + extensions
        val handshake = byteArrayOf(1, 0, (body.size shr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(22, 3, 1) + u16(handshake.size) + handshake
    }

    @Test
    fun `fingerprints read the version, name, counts and ALPN, without GREASE`() {
        val prints = TlsFingerprint.fromClientHello(clientHello())
        assertNotNull(prints)
        // TLS 1.3, SNI present, 3 ciphers without GREASE, 6 extensions without GREASE, ALPN h2
        assertTrue(prints!!.ja4, prints.ja4.startsWith("t13d0306h2_"))
        assertEquals(32, prints.ja3.length)
    }

    @Test
    fun `no name and no ALPN show in the fingerprint`() {
        val prints = TlsFingerprint.fromClientHello(clientHello(sni = null, alpn = null))
        assertTrue(prints!!.ja4, prints.ja4.startsWith("t13i030400_"))
    }

    @Test
    fun `a ClientHello split across two segments is put back together`() {
        val hello = clientHello()
        val middle = hello.size / 2
        start(50000, 443)

        val first = tcpPacket(50000, 443, psh, hello.copyOfRange(0, middle))
        val firstRecord = PacketRecord.fromIpPacket(first, true, PacketRecord.MODE_VPN)!!
        val (partial, _) = PacketPipeline.dissectAndEnrich(firstRecord, first)
        @Suppress("UNCHECKED_CAST")
        assertNull((partial["tlsData"] as? Map<String, String>)?.get("ja4"))

        val second = tcpPacket(50000, 443, psh, hello.copyOfRange(middle, hello.size))
        val secondRecord = PacketRecord.fromIpPacket(second, true, PacketRecord.MODE_VPN)!!
        val (whole, _) = PacketPipeline.dissectAndEnrich(secondRecord, second)
        @Suppress("UNCHECKED_CAST")
        val tls = whole["tlsData"] as Map<String, String>
        assertEquals(TlsFingerprint.fromClientHello(hello)!!.ja4, tls["ja4"])
        assertEquals("example.com", tls["sni"])
    }

    @Test
    fun `a claimed hello larger than the bound is not buffered`() {
        val huge = byteArrayOf(22, 3, 1, 0x7F, 0xFF.toByte(), 1) + ByteArray(100)
        start(50000, 443)
        run(tcpPacket(50000, 443, psh, huge))
        run(tcpPacket(50000, 443, psh, ByteArray(100)))
        assertFalse(alerts.any { it.description.contains("FLOW") })
    }

    @Test
    fun `a truncated ClientHello gives no fingerprint`() {
        val hello = clientHello()
        assertNull(TlsFingerprint.fromClientHello(hello.copyOf(hello.size - 5)))
    }

    @Test
    fun `other bytes give no fingerprint`() {
        assertNull(TlsFingerprint.fromClientHello(random(300)))
        assertNull(TlsFingerprint.fromClientHello(ByteArray(0)))
    }

    @Test
    fun `the fingerprint reaches the record through the pipeline`() {
        val packet = tcpPacket(50000, 443, psh, clientHello())
        val record = PacketRecord.fromIpPacket(packet, true, PacketRecord.MODE_VPN)!!
        val (enriched, _) = PacketPipeline.dissectAndEnrich(record, packet)
        @Suppress("UNCHECKED_CAST")
        val tls = enriched["tlsData"] as Map<String, String>
        assertNotNull(tls["ja4"])
        assertEquals("example.com", tls["sni"])
    }
}
