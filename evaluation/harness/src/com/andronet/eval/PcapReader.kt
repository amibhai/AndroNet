package com.andronet.eval

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.util.zip.GZIPInputStream

/** One captured frame, timestamped in microseconds since the epoch. */
class Frame(val tsUs: Long, val linktype: Int, val data: ByteArray)

/** Streaming reader for classic pcap and pcapng files, optionally gzip-compressed. */
class PcapReader(file: File) : Closeable {
    private val input: DataInputStream
    private var next: Frame? = null

    // pcap state
    private var isPcapng = false
    private var bigEndian = false
    private var nanos = false
    private var pcapLinktype = 1

    // pcapng state, one entry per interface description block
    private val ifLink = ArrayList<Int>()
    private val ifTsDiv = ArrayList<Long>() // ticks per microsecond divisor (0 = multiply)
    private val ifTsMul = ArrayList<Long>()

    init {
        val raw = BufferedInputStream(FileInputStream(file), 1 shl 16)
        raw.mark(4)
        val b0 = raw.read()
        val b1 = raw.read()
        raw.reset()
        val stream = if (b0 == 0x1f && b1 == 0x8b) BufferedInputStream(GZIPInputStream(raw), 1 shl 16) else raw
        input = DataInputStream(stream)
        readGlobalHeader()
    }

    private fun readGlobalHeader() {
        val magic = input.readInt()
        when (magic) {
            0xA1B2C3D4.toInt() -> { bigEndian = true; nanos = false }
            0xD4C3B2A1.toInt() -> { bigEndian = false; nanos = false }
            0xA1B23C4D.toInt() -> { bigEndian = true; nanos = true }
            0x4D3CB2A1.toInt() -> { bigEndian = false; nanos = true }
            0x0A0D0D0A -> { isPcapng = true; readSectionHeaderBody(); return }
            else -> throw IllegalArgumentException("Not a pcap or pcapng file: magic=%08x".format(magic))
        }
        input.skipBytes(16) // version, thiszone, sigfigs, snaplen
        pcapLinktype = i32()
    }

    private fun i32(): Int {
        val v = input.readInt()
        return if (bigEndian) v else Integer.reverseBytes(v)
    }

    private fun u16(): Int {
        val v = input.readUnsignedShort()
        return if (bigEndian) v else (java.lang.Short.reverseBytes(v.toShort()).toInt() and 0xFFFF)
    }

    private fun skipFully(n: Long) {
        var left = n
        while (left > 0) {
            val skipped = input.skip(left)
            if (skipped <= 0) {
                input.readByte()
                left -= 1
            } else {
                left -= skipped
            }
        }
    }

    private fun readSectionHeaderBody() {
        val lenBytes = ByteArray(4)
        input.readFully(lenBytes)
        val bom = input.readInt()
        bigEndian = bom == 0x1A2B3C4D
        val total = if (bigEndian) {
            ((lenBytes[0].toInt() and 0xFF) shl 24) or ((lenBytes[1].toInt() and 0xFF) shl 16) or
                ((lenBytes[2].toInt() and 0xFF) shl 8) or (lenBytes[3].toInt() and 0xFF)
        } else {
            ((lenBytes[3].toInt() and 0xFF) shl 24) or ((lenBytes[2].toInt() and 0xFF) shl 16) or
                ((lenBytes[1].toInt() and 0xFF) shl 8) or (lenBytes[0].toInt() and 0xFF)
        }
        skipFully((total - 12).toLong())
        ifLink.clear(); ifTsDiv.clear(); ifTsMul.clear()
    }

    fun read(): Frame? {
        if (next != null) { val f = next; next = null; return f }
        return try {
            if (isPcapng) readPcapngFrame() else readPcapFrame()
        } catch (e: EOFException) {
            null
        }
    }

    private fun readPcapFrame(): Frame? {
        val sec = i32().toLong() and 0xFFFFFFFFL
        val frac = i32().toLong() and 0xFFFFFFFFL
        val caplen = i32()
        i32() // original length
        if (caplen < 0 || caplen > 16 * 1024 * 1024) return null
        val data = ByteArray(caplen)
        input.readFully(data)
        val us = if (nanos) frac / 1000 else frac
        return Frame(sec * 1_000_000L + us, pcapLinktype, data)
    }

    private fun readPcapngFrame(): Frame? {
        while (true) {
            val type = input.readInt().let { if (bigEndian) it else Integer.reverseBytes(it) }
            if (type == 0x0A0D0D0A) { readSectionHeaderBody(); continue }
            val total = i32()
            if (total < 12) return null
            val body = total - 12
            when (type) {
                1 -> { // Interface Description Block
                    val link = u16()
                    input.readUnsignedShort()
                    i32() // snaplen
                    var remaining = body - 8
                    var div = 1L
                    var mul = 1L
                    while (remaining >= 4) {
                        val code = u16()
                        val len = u16()
                        remaining -= 4
                        val pad = (4 - (len % 4)) % 4
                        if (code == 9 && len >= 1) { // if_tsresol
                            val r = input.readUnsignedByte()
                            skipFully((len - 1).toLong())
                            val ticks = if (r and 0x80 != 0) Math.pow(2.0, (r and 0x7F).toDouble()) else Math.pow(10.0, r.toDouble())
                            if (ticks >= 1_000_000.0) { div = (ticks / 1_000_000.0).toLong(); mul = 1 } else { div = 1; mul = (1_000_000.0 / ticks).toLong() }
                        } else {
                            skipFully(len.toLong())
                        }
                        skipFully(pad.toLong())
                        remaining -= len + pad
                        if (code == 0) break
                    }
                    if (remaining > 0) skipFully(remaining.toLong())
                    ifLink.add(link); ifTsDiv.add(div); ifTsMul.add(mul)
                    i32() // trailing total length
                }
                6 -> { // Enhanced Packet Block
                    val ifId = i32()
                    val hi = i32().toLong() and 0xFFFFFFFFL
                    val lo = i32().toLong() and 0xFFFFFFFFL
                    val caplen = i32()
                    i32() // original length
                    val data = ByteArray(caplen)
                    input.readFully(data)
                    val consumed = 20 + caplen
                    skipFully((body - consumed).toLong())
                    i32()
                    val ticks = (hi shl 32) or lo
                    val idx = if (ifId in ifLink.indices) ifId else 0
                    val link = ifLink.getOrElse(idx) { 1 }
                    val us = ticks / ifTsDiv.getOrElse(idx) { 1L } * ifTsMul.getOrElse(idx) { 1L }
                    return Frame(us, link, data)
                }
                3 -> { // Simple Packet Block carries no timestamp, so it cannot drive the windows
                    skipFully(body.toLong()); i32()
                }
                else -> { skipFully(body.toLong()); i32() }
            }
        }
    }

    override fun close() = input.close()
}

/** What a capture back-end actually hands to the record builder. */
sealed class NetUnit {
    class Ip(val packet: ByteArray) : NetUnit()
    class Arp(val senderMac: String, val senderIp: String, val targetIp: String, val opcode: Int, val raw: ByteArray) : NetUnit()
}

object LinkLayer {
    /** Strips the link-layer header of [f]. Returns null for anything that is neither IP nor ARP. */
    fun strip(f: Frame): NetUnit? {
        val d = f.data
        return when (f.linktype) {
            1 -> { // Ethernet, optionally 802.1Q-tagged
                if (d.size < 14) return null
                var off = 12
                var ethertype = u16(d, off)
                while ((ethertype == 0x8100 || ethertype == 0x88A8) && d.size >= off + 6) {
                    off += 4
                    ethertype = u16(d, off)
                }
                fromEthertype(ethertype, d, off + 2)
            }
            0, 108 -> { // BSD/Windows loopback: 4-byte address family in host or network order
                if (d.size < 5) return null
                ip(d, 4)
            }
            101, 12, 14 -> ip(d, 0)
            113 -> { // Linux cooked v1
                if (d.size < 16) return null
                fromEthertype(u16(d, 14), d, 16)
            }
            276 -> { // Linux cooked v2
                if (d.size < 20) return null
                fromEthertype(u16(d, 0), d, 20)
            }
            else -> null
        }
    }

    private fun fromEthertype(ethertype: Int, d: ByteArray, off: Int): NetUnit? = when (ethertype) {
        0x0800, 0x86DD -> ip(d, off)
        0x0806 -> arp(d, off)
        else -> null
    }

    private fun ip(d: ByteArray, off: Int): NetUnit? {
        if (d.size <= off) return null
        val version = (d[off].toInt() shr 4) and 0x0F
        if (version != 4 && version != 6) return null
        return NetUnit.Ip(d.copyOfRange(off, d.size))
    }

    private fun arp(d: ByteArray, off: Int): NetUnit? {
        if (d.size < off + 28) return null
        if (u16(d, off) != 1 || u16(d, off + 2) != 0x0800) return null // Ethernet/IPv4 ARP only
        val mac = (0 until 6).joinToString(":") { "%02x".format(d[off + 8 + it]) }
        val spa = (0 until 4).joinToString(".") { (d[off + 14 + it].toInt() and 0xFF).toString() }
        val tpa = (0 until 4).joinToString(".") { (d[off + 24 + it].toInt() and 0xFF).toString() }
        return NetUnit.Arp(mac, spa, tpa, u16(d, off + 6), d.copyOfRange(off, d.size))
    }

    private fun u16(d: ByteArray, off: Int) = ((d[off].toInt() and 0xFF) shl 8) or (d[off + 1].toInt() and 0xFF)
}
