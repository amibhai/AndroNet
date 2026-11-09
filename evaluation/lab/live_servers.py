#!/usr/bin/env python3
"""Endpoints on the laptop for live traffic from the phone. Run while a live experiment is going.

  18081/tcp  source: streams N bytes per connection, optionally rate-limited
  18082/tcp  sink: reads and discards
  18080/tcp  HTTP endpoint for attack requests, plus 22, 3333, 4444, 6667 protocol endpoints
  53/udp     DNS sink

Serves only for the duration of the experiment and only speaks these canned exchanges.
"""
import argparse
import socket
import socketserver
import sys
import threading
import time
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import lab_servers as lab  # noqa: E402

CHUNK = bytes(range(256)) * 256  # 64 KiB of fixed bytes: incompressible enough, and no CPU spent generating it


class Source(socketserver.BaseRequestHandler):
    def handle(self):
        # First line: "<bytes> <rate_mbit, 0 = unlimited>"
        line = b""
        while not line.endswith(b"\n"):
            b = self.request.recv(1)
            if not b:
                return
            line += b
        total, rate = line.split()
        total, rate = int(total), float(rate)
        sent = 0
        start = time.time()
        try:
            while sent < total:
                n = min(len(CHUNK), total - sent)
                self.request.sendall(CHUNK[:n])
                sent += n
                if rate > 0:
                    due = start + sent * 8 / (rate * 1e6)
                    delay = due - time.time()
                    if delay > 0:
                        time.sleep(delay)
        except OSError:
            pass
        if rate > 0:
            # Paced streams are the energy runs' workload: the log lets each run be checked afterwards
            seconds = time.time() - start
            print(f"stream {time.strftime('%H:%M:%S')} rate={rate:g} sent={sent} seconds={seconds:.0f} "
                  f"achieved={sent * 8 / max(seconds, 1) / 1e6:.1f} Mbit/s", flush=True)


class Threaded(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def lines(port, banner=b"", replies=None, default=b""):
    cls = type("H%d" % port, (lab.LineHandler,), {"banner": banner, "replies": replies or {}, "default": default})
    srv = Threaded(("0.0.0.0", port), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=3600)
    args = ap.parse_args()

    for port, handler in ((18081, Source), (18082, lab.SinkHandler)):
        srv = Threaded(("0.0.0.0", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    http = lab.ReuseHTTP(("0.0.0.0", 18080), lab.Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()

    lines(22, b"SSH-2.0-OpenSSH_9.6\r\n", default=b"")
    lines(3333, replies={b"subscribe": b'{"id":1,"result":[],"error":null}\n', b"login": b'{"id":1,"result":{"status":"OK"}}\n'})
    lines(4444, default=b"\x00\x00\x00\x08ack\n")
    lines(6667, b":irc.local NOTICE * :hello\r\n", default=b":irc.local 001 x :ok\r\n")

    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("0.0.0.0", 53))

    def dns_loop():
        while True:
            data, peer = dns.recvfrom(4096)
            if len(data) >= 12:  # echo the question back as an empty answer
                reply = bytearray(data)
                reply[2] |= 0x80
                dns.sendto(bytes(reply), peer)

    threading.Thread(target=dns_loop, daemon=True).start()

    print("live servers up", flush=True)
    time.sleep(args.seconds)


if __name__ == "__main__":
    main()
