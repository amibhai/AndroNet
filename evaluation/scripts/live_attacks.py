#!/usr/bin/env python3
"""Runs the attack generator on the phone through a live capture and scores what the app reported.

  python live_attacks.py --tag dev

The evaluation build logs each alert it raises; those log lines are matched to the generator's
scenario windows by timestamp. The harness dex carries the generator, and nothing in the
detection path knows it is being tested.
"""
import argparse
import json
import pathlib
import re
import subprocess
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]

# What each scenario should raise, by the id the alert carries.
EXPECTED = {
    "port_scan_connect": {"L1:PORT_SCAN", "RULE-001"},
    "syn_flood": {"L1:SYN_FLOOD"},
    "http_sqli": {"EXP-001", "RULE-002"},
    "http_traversal": {"EXP-002"},
    "http_scanner_sqlmap_ua": {"RECON-003", "RULE-009"},
    "http_scanner_nikto_ua": {"RECON-002", "RULE-009"},
    "http_scanner_nmap_ua": {"RECON-001", "RULE-009"},
    "http_shellshock": {"NET-002"},
    "http_rce": {"EXP-003"},
    "http_xxe": {"EXP-004"},
    "http_download": {"RULE-003"},
    "http_cobalt_beacon": {"MAL-003"},
    "http_exfil": {"EXFIL-001", "RULE-007"},
    "dns_tunnel_fast": {"L1:DNS_TUNNELING", "RULE-004"},
    "dns_tunnel_slow": {"L1:DNS_TUNNELING"},
    "stratum_btc": {"RULE-006"},
    "stratum_xmrig": {"RULE-006"},
    "irc_bot": {"C2-003"},
    "meterpreter": {"MAL-001"},
    "ssh_tool_banner": {"BRUTE-001"},
    "ssh_bruteforce": {"RULE-005"},
    "shellcode": {"RULE-008"},
}

ALERT = re.compile(r"^\s*(\d+)\.(\d+)\s.*ANOMALY: (\S+) - (.*)$")
TAG = re.compile(r"^\[([A-Z0-9-]+)\]")


def alert_id(kind, description):
    m = TAG.match(description)
    return m.group(1) if m else "L1:" + kind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.1.8")
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--only", default="")
    ap.add_argument("--learn", type=int, default=62, help="seconds to let the learning period pass")
    args = ap.parse_args()

    phone.push_harness()
    phone.stop_andronet()
    if not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    phone.home()
    print(f"learning period: waiting {args.learn} s", flush=True)
    time.sleep(args.learn)
    phone.adb("logcat", "-c")

    # Streamed, not read back at the end: per-connection log lines rotate the phone's buffer
    # within minutes, which would silently lose the alerts of the earliest scenarios.
    log_path = EVAL / "results" / f"live_attacks_{args.tag}.logcat"
    log_file = open(log_path, "wb")
    streamer = subprocess.Popen(["adb", "logcat", "-v", "epoch", "-s", "PacketAnalysisManager:W"],
                                env=phone.ENV, stdout=log_file, stderr=subprocess.DEVNULL)

    only = f"--only {args.only}" if args.only else ""
    out = phone.harness(f"livegen --host {args.host} {only} --out {phone.D}/live.txt", timeout=1500)
    print(out, flush=True)
    time.sleep(3)

    windows = []
    for line in phone.shell(f"cat {phone.D}/live.txt").splitlines():
        name, start, end = line.split()
        windows.append((name, int(start), int(end)))

    streamer.terminate()
    streamer.wait(5)
    log_file.close()
    log = log_path.read_text(encoding="utf-8", errors="replace")
    pid = phone.pid_of(phone.EVAL_PKG)
    rss = phone.rss_kib(pid) // 1024
    phone.stop_andronet()

    results = {}
    other = {}
    for raw in log.splitlines():
        m = ALERT.match(raw)
        if not m:
            continue
        ts = int(m.group(1)) * 1000 + int(m.group(2))
        aid = alert_id(m.group(3), m.group(4))
        for name, start, end in windows:
            # The settle gap after a scenario still belongs to it: rate rules fire late
            if start <= ts <= end + 9000:
                results.setdefault(name, {}).setdefault(aid, 0)
                results[name][aid] += 1
                break
        else:
            other[aid] = other.get(aid, 0) + 1

    detected = 0
    table = []
    for name, _, _ in windows:
        got = results.get(name, {})
        hit = sorted(EXPECTED.get(name, set()) & set(got))
        ok = bool(hit)
        detected += ok
        table.append({"scenario": name, "detected": ok, "expected": sorted(EXPECTED.get(name, [])), "alerts": got})
        print(f"{'OK  ' if ok else 'MISS'} {name:26s} {got}", flush=True)
    print(f"detected {detected}/{len(windows)}; alerts outside any window: {other}; app rss={rss} MiB")

    (EVAL / "results" / f"live_attacks_{args.tag}.json").write_text(json.dumps(
        {"host": args.host, "detected": detected, "total": len(windows), "scenarios": table, "outside": other, "rssMiB": rss}, indent=1))


if __name__ == "__main__":
    main()
