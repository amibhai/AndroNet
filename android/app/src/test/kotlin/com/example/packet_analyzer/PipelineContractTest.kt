package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Runs real wire bytes through PacketRecord, PacketPipeline and detection together.
 *
 * The rule and signature tests build records by hand, which is how the dissector and the
 * detectors once came to disagree on field names ("uri" against "url", "userAgent" against
 * "User-Agent") while both test suites stayed green. These tests can only pass if the fields
 * the dissector writes are the fields detection reads.
 */
class PipelineContractTest {

    private val alerts = mutableListOf<AnomalyDetector.Anomaly>()
    private val listener: (AnomalyDetector.Anomaly) -> Unit = { alerts.add(it) }

    @Before
    fun setUp() {
        AnomalyDetector.reset()
        AnomalyDetector.adaptiveThresholds.reset()
        RuleEngine.clearState()
        DomainTracker.clear()
        AnomalyDetector.removeAnomalyListener(listener)
        AnomalyDetector.addAnomalyListener(listener)
        alerts.clear()
    }

    private fun tcpPacket(
        srcPort: Int,
        dstPort: Int,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        srcIp: ByteArray = byteArrayOf(192.toByte(), 0, 2, 10),
        dstIp: ByteArray = byteArrayOf(192.toByte(), 0, 2, 20)
    ): ByteArray {
        val total = 40 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = total.toByte()
        p[8] = 64
        p[9] = 6
        srcIp.copyInto(p, 12)
        dstIp.copyInto(p, 16)
        p[20] = (srcPort shr 8).toByte()
        p[21] = srcPort.toByte()
        p[22] = (dstPort shr 8).toByte()
        p[23] = dstPort.toByte()
        p[32] = 0x50
        p[33] = flags.toByte()
        payload.copyInto(p, 40)
        return p
    }

    private fun run(packet: ByteArray, outgoing: Boolean = true, mode: String = PacketRecord.MODE_VPN) {
        val record = PacketRecord.fromIpPacket(packet, outgoing, mode)!!
        val (enriched, payload) = PacketPipeline.dissectAndEnrich(record, packet)
        PacketPipeline.analyze(enriched, payload)
    }

    private fun fired(id: String) = alerts.any { it.description.startsWith("[$id]") }

    private val psh = 0x18

    private fun http(request: String) = tcpPacket(50000, 80, psh, request.toByteArray())

    @Test
    fun `scanner user agent reaches the header signatures`() {
        run(http("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.9#stable (https://sqlmap.org)\r\n\r\n"))
        assertTrue(fired("RECON-003"))
        assertTrue(fired("RULE-009"))
    }

    @Test
    fun `header names match whatever case the client sent`() {
        run(http("GET / HTTP/1.1\r\nhost: x\r\nuser-agent: sqlmap/1.9\r\n\r\n"))
        assertTrue(fired("RECON-003"))
    }

    @Test
    fun `percent-encoded SQL injection reaches the URL signature and rule`() {
        run(http("GET /item?id=1%20UNION%20SELECT%201,2 HTTP/1.1\r\nHost: x\r\n\r\n"))
        assertTrue(fired("EXP-001"))
        assertTrue(fired("RULE-002"))
    }

    @Test
    fun `percent-encoded traversal reaches the URL signature`() {
        run(http("GET /f?p=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: x\r\n\r\n"))
        assertTrue(fired("EXP-002"))
    }

    @Test
    fun `executable download reaches the file rule`() {
        run(http("GET /updates/setup.exe HTTP/1.1\r\nHost: x\r\n\r\n"))
        assertTrue(fired("RULE-003"))
    }

    @Test
    fun `HTTP on an unusual port is still dissected`() {
        run(tcpPacket(50000, 8000, psh, "GET /a.exe HTTP/1.1\r\nHost: x\r\n\r\n".toByteArray()))
        assertTrue(fired("RULE-003"))
    }

    @Test
    fun `request body in its own segment still counts as a request`() {
        run(http("<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>"))
        assertTrue(fired("EXP-004"))
    }

    @Test
    fun `an ordinary web page raises nothing`() {
        val page = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><script>eval(x)</script></html>"
        run(tcpPacket(80, 50000, psh, page.toByteArray()), outgoing = false)
        assertTrue("Unexpected alerts: ${alerts.map { it.description }}", alerts.isEmpty())
    }

    @Test
    fun `ciphertext is withheld from payload matching`() {
        // Bytes that would fire the shellcode rule if port 443 payloads were inspected
        val looksLikeShellcode = ByteArray(40) { 0x90.toByte() }
        run(tcpPacket(50000, 443, psh, looksLikeShellcode))
        assertFalse(fired("RULE-008"))
    }

    @Test
    fun `replies from one server do not look like a port scan`() {
        for (port in 40000..40100) {
            run(tcpPacket(443, port, 0x10), outgoing = false)
        }
        assertFalse(alerts.any { it.type == AnomalyDetector.AnomalyType.PORT_SCAN })
    }

    @Test
    fun `probes without ACK are counted as a port scan`() {
        for (port in 1..25) {
            run(tcpPacket(50000, port, 0x02))
        }
        assertTrue(alerts.any { it.type == AnomalyDetector.AnomalyType.PORT_SCAN })
    }

    @Test
    fun `a SYN flood reaches its threshold`() {
        for (i in 1..150) {
            run(tcpPacket(1024 + i, 80, 0x02))
        }
        assertTrue(alerts.any { it.type == AnomalyDetector.AnomalyType.SYN_FLOOD })
    }

    @Test
    fun `both capture modes produce identical alerts for the same packets`() {
        val request = "GET /a.exe?id=1%20UNION%20SELECT%201 HTTP/1.1\r\nHost: x\r\nUser-Agent: Nikto/2.5\r\n\r\n"
        run(http(request), mode = PacketRecord.MODE_VPN)
        val viaVpn = alerts.map { it.description }.sorted()

        setUp()
        run(http(request), mode = PacketRecord.MODE_ROOT)
        val viaRoot = alerts.map { it.description }.sorted()

        assertTrue(viaVpn.isNotEmpty())
        assertEquals(viaVpn, viaRoot)
    }

    @Test
    fun `an ARP binding change raises an alert`() {
        val first = PacketRecord.fromArp("00:11:22:33:44:55", "192.0.2.1", "192.0.2.10", 28, false, PacketRecord.MODE_ROOT)
        val second = PacketRecord.fromArp("66:77:88:99:aa:bb", "192.0.2.1", "192.0.2.10", 28, false, PacketRecord.MODE_ROOT)
        PacketPipeline.analyze(first.toMutableMap(), null)
        assertTrue(alerts.isEmpty())
        PacketPipeline.analyze(second.toMutableMap(), null)
        assertTrue(alerts.any { it.type == AnomalyDetector.AnomalyType.ARP_SPOOFING })
    }

    @Test
    fun `DNS question name reaches the domain predicates`() {
        // Header: id, RD flag, one question; then labels for beacon.evil-command-control.net
        val name = "beacon.evil-command-control.net"
        val question = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }.toByteArray() +
            byteArrayOf(0, 0, 1, 0, 1)
        val dns = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) + question
        val total = 28 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte()
        p[3] = total.toByte()
        p[9] = 17
        byteArrayOf(192.toByte(), 0, 2, 10).copyInto(p, 12)
        byteArrayOf(192.toByte(), 0, 2, 53).copyInto(p, 16)
        p[20] = (40000 shr 8).toByte()
        p[21] = 40000.toByte()
        p[23] = 53
        dns.copyInto(p, 28)
        run(p)
        assertTrue(fired("C2-002"))
    }
}
