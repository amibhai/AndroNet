#!/usr/bin/env python3
"""Does a TCP connection survive going quiet inside the tunnel?

Apps hold long-lived connections for push messages and send on them only now and then, so a relay that
forgets a connection after a short silence breaks them without either end being told. Each case opens a
connection from the phone to an echo server on the laptop, sends a line, stays quiet for a set time,
sends a second line and sees whether it comes back.

  python idle_probe.py --tag current_vpn --mode andronet --host 192.168.1.8
"""
import argparse
import concurrent.futures
import json
import pathlib
import socketserver
import threading
import time

import phone
from throughput_final import start_pcapdroid, stop_pcapdroid

EVAL = pathlib.Path(__file__).resolve().parents[1]
PORT = 18099
IDLE_SECONDS = (30, 90, 300)


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write(line)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def case(host, idle):
    # The second line must come back through the same connection, so only a reply to it counts
    out = phone.shell(f"(echo first; sleep {idle}; echo second-{idle}; sleep 8) | nc -q 2 {host} {PORT}", check=False, timeout=idle + 60)
    return {"idleSeconds": idle, "firstBack": "first" in out, "secondBack": f"second-{idle}" in out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.1.8")
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--mode", default="andronet", choices=["none", "andronet", "pcapdroid"])
    args = ap.parse_args()

    server = Server(("0.0.0.0", PORT), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    if args.mode == "andronet" and not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    if args.mode == "pcapdroid" and not start_pcapdroid("none"):
        raise SystemExit("PCAPdroid did not come up")
    phone.home()
    time.sleep(2)

    with concurrent.futures.ThreadPoolExecutor(len(IDLE_SECONDS)) as pool:
        results = list(pool.map(lambda idle: case(args.host, idle), IDLE_SECONDS))

    if args.mode == "andronet":
        phone.stop_andronet()
    if args.mode == "pcapdroid":
        stop_pcapdroid()
    out = {"mode": args.mode, "cases": results}
    (EVAL / "results" / f"idle_probe_{args.tag}.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
