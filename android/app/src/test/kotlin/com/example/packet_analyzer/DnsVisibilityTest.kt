package com.example.packet_analyzer

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsVisibilityTest {
    private fun v4(protocol: Int, dstIp: String, dstPort: Int): ByteArray {
        val p = ByteArray(40)
        p[0] = 0x45
        p[9] = protocol.toByte()
        dstIp.split('.').forEachIndexed { i, b -> p[16 + i] = b.toInt().toByte() }
        p[22] = (dstPort shr 8).toByte()
        p[23] = dstPort.toByte()
        return p
    }

    private fun v6(protocol: Int, suffix: Int, dstPort: Int, resolverPrefix: Boolean = true): ByteArray {
        val p = ByteArray(60)
        p[0] = 0x60
        p[6] = protocol.toByte()
        val prefix = if (resolverPrefix) byteArrayOf(0x20, 0x01, 0x48, 0x60, 0x48, 0x60) else byteArrayOf(0x26, 0x07, 0x48, 0x60, 0x48, 0x60)
        prefix.copyInto(p, 24)
        p[38] = (suffix shr 8).toByte()
        p[39] = suffix.toByte()
        p[42] = (dstPort shr 8).toByte()
        p[43] = dstPort.toByte()
        return p
    }

    @Test
    fun `DNS over TLS is refused wherever it goes`() {
        assertTrue(DnsVisibility.isEncryptedDns(v4(6, "1.1.1.1", 853)))
        assertTrue(DnsVisibility.isEncryptedDns(v4(6, "8.8.8.8", 853)))
    }

    @Test
    fun `DNS over HTTPS to the tunnel's resolvers is refused, over TCP and QUIC`() {
        assertTrue(DnsVisibility.isEncryptedDns(v4(6, "8.8.8.8", 443)))
        assertTrue(DnsVisibility.isEncryptedDns(v4(17, "8.8.4.4", 443)))
        assertTrue(DnsVisibility.isEncryptedDns(v6(6, 0x8888, 443)))
        assertTrue(DnsVisibility.isEncryptedDns(v6(17, 0x8844, 443)))
    }

    @Test
    fun `plain DNS and ordinary web traffic pass`() {
        assertFalse(DnsVisibility.isEncryptedDns(v4(17, "8.8.8.8", 53)))
        assertFalse(DnsVisibility.isEncryptedDns(v4(6, "142.250.1.1", 443)))
        assertFalse(DnsVisibility.isEncryptedDns(v6(6, 0x8888, 53)))
        assertFalse(DnsVisibility.isEncryptedDns(v6(6, 0x8888, 443, resolverPrefix = false)))
    }

    @Test
    fun `malformed packets are left alone`() {
        assertFalse(DnsVisibility.isEncryptedDns(ByteArray(0)))
        assertFalse(DnsVisibility.isEncryptedDns(byteArrayOf(0x45, 0, 0)))
        assertFalse(DnsVisibility.isEncryptedDns(ByteArray(10) { 0x60 }))
    }
}
