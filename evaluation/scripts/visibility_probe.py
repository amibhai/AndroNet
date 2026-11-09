#!/usr/bin/env python3
"""Shows what the VPN path cannot see: real nmap scans of the phone from the laptop.

The phone runs VPN-mode capture. The laptop scans it across the LAN. Traffic from the phone's own
apps enters the tunnel; packets arriving unsolicited at wlan0 never do. So any alert or tunnel
packet for the scan would contradict the observability table in the paper.
"""
import json
import pathlib
import re
import subprocess
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]
NMAP = next((EVAL / "tools/nmap").rglob("nmap.exe"))
PHONE_IP = "192.168.1.4"
LAB_IP = "192.168.1.8"


def ports_answered(nmap_output):
    """Ports the phone's kernel answered. The user build hides interface counters, so this is the
    evidence that the probes really arrived: a closed port's reset can only come from the phone."""
    m = re.search(r"(\d+) closed tcp ports? \(reset\)", nmap_output)
    if m:
        return int(m.group(1))
    return len(re.findall(r"^\d+/tcp\s+closed", nmap_output, re.M))


def main():
    phone.stop_andronet()
    if not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    phone.home()
    print("learning period: 62 s", flush=True)
    time.sleep(62)

    log_path = EVAL / "results" / "visibility.logcat"
    log_file = open(log_path, "wb")
    phone.adb("logcat", "-c")
    streamer = subprocess.Popen(["adb", "logcat", "-v", "epoch", "-s", "PacketAnalysisManager:W"],
                                env=phone.ENV, stdout=log_file, stderr=subprocess.DEVNULL)

    results = {}
    # Raw scans only: each draws a reset from every closed port, which proves delivery. A connect
    # scan through the laptop's own TCP stack reported every port filtered here, proving nothing.
    for name, flags in (("syn", ["-sS"]), ("null", ["-sN"]), ("xmas", ["-sX"])):
        # The phone's Wi-Fi sleeps between beacons, and one lost ARP reply would mark the host down
        subprocess.run(["ping", "-n", "3", PHONE_IP], capture_output=True)
        start = int(phone.shell("date +%s").strip())
        run = subprocess.run([str(NMAP), *flags, "-Pn", "-n", "-p1-1000", "-T4", "--max-retries", "1", PHONE_IP],
                             capture_output=True, text=True, timeout=200)
        end = int(phone.shell("date +%s").strip())
        results[name] = {"portsAnswered": ports_answered(run.stdout), "start": start, "end": end, "nmapTail": run.stdout.strip().splitlines()[-4:]}
        print(name, results[name], flush=True)
        time.sleep(3)

    streamer.terminate()
    streamer.wait(5)
    log_file.close()
    phone.stop_andronet()

    alerts = []
    for raw in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"^\s*(\d+)\.\d+\s.*ANOMALY: (\S+) - (.*)$", raw)
        if m:
            alerts.append((int(m.group(1)), m.group(2), m.group(3)[:60]))
    scan_alerts = [a for a in alerts if a[1] in ("PORT_SCAN", "SYN_FLOOD", "CONNECTION_FLOOD", "MALFORMED_PACKET")]
    print("all alerts during scans:", alerts)
    results["scanAlerts"] = len(scan_alerts)
    results["allAlerts"] = len(alerts)
    (EVAL / "results" / "visibility.json").write_text(json.dumps(results, indent=1))
    print("scan-related alerts:", len(scan_alerts))


if __name__ == "__main__":
    main()
