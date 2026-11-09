#!/usr/bin/env python3
"""Exercises the root capture path end to end on a rootable emulator.

Sets up a su stand-in, starts AndroNet's root capture (helper through su, AF_PACKET, shared
pipeline), then produces two kinds of traffic and scores the alerts the app raises:

  * the same on-device attack scenarios as the VPN experiment (live_attacks.py), and
  * frames injected on the interface: inbound scans and ARP spoofing, which a VPN cannot see.

Run with ANDROID_SERIAL=emulator-5554. Never run this against a real phone: it disables SELinux
enforcement and replaces su.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import time

os.environ.setdefault("ANDROID_SERIAL", "emulator-5554")
import phone  # noqa: E402
from live_attacks import ALERT, EXPECTED, alert_id  # noqa: E402

# Needs to know which app sent a packet, which only the VPN path can tell
VPN_ONLY = {"tls_library_switch"}

EVAL = pathlib.Path(__file__).resolve().parents[1]
HOST = "10.0.2.2"  # the emulator's alias for the laptop

# Frames injected on the interface, with what each should raise.
INJECTED = {
    "inbound_nmap_syn": ("atk_nmap_syn", {"L1:PORT_SCAN"}),
    "inbound_nmap_fin": ("atk_nmap_fin", {"L1:PORT_SCAN"}),
    "inbound_nmap_null": ("atk_nmap_null", {"L1:PORT_SCAN"}),
    "inbound_nmap_xmas": ("atk_nmap_xmas", {"L1:PORT_SCAN"}),
    "inbound_nmap_synfin": ("atk_nmap_synfin", {"L1:MALFORMED_PACKET"}),
    "inbound_syn_flood": ("atk_syn_flood", {"L1:SYN_FLOOD"}),
    "arp_spoof": ("atk_arp_spoof", {"L1:ARP_SPOOFING"}),
}


def setup(apk):
    serial = phone.ENV["ANDROID_SERIAL"]
    if not serial.startswith("emulator-"):
        raise SystemExit("refusing to run on anything but an emulator")
    phone.adb("root")
    time.sleep(4)
    phone.shell("setenforce 0")
    phone.shell(f"mkdir -p {phone.D}/t")
    print(phone.adb("install", "-r", str(apk)).strip()[-20:], flush=True)
    phone.adb("push", str(EVAL / "lab/emulator_su.sh"), f"{phone.D}/su")
    phone.adb("push", str(EVAL / "build/native/x86_64/pcap_inject"), f"{phone.D}/pcap_inject")
    phone.shell(f"chmod 755 {phone.D}/su {phone.D}/pcap_inject; chmod 755 {phone.D}; chmod 755 /data/local/tmp")
    # Apps fork from zygote and inherit its mount namespace, so that is where su must change.
    # It sits on its own tmpfs because a file bind-mounted out of /data cannot be executed by an app.
    phone.shell(f"nsenter -t $(pidof zygote64) -m -- sh -c 'umount /system/xbin 2>/dev/null; "
                f"mount -t tmpfs -o exec,mode=755 tmpfs /system/xbin && cp {phone.D}/su /system/xbin/su && "
                f"chmod 755 /system/xbin/su && chcon u:object_r:system_file:s0 /system/xbin/su'", check=False)
    # The listener plays the part of a root manager's daemon, which owns full capabilities
    phone.shell("pkill -f 'nc -L -s 127.0.0.1 -p 5999' ; true", check=False)
    subprocess.Popen(["adb", "shell", "nohup nc -L -s 127.0.0.1 -p 5999 sh -c 'read cmd; exec $cmd' >/dev/null 2>&1 &"],
                     env=phone.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    phone.push_harness()
    phone.shell(f"appops set {phone.EVAL_PKG} ACTIVATE_VPN allow; pm grant {phone.EVAL_PKG} android.permission.POST_NOTIFICATIONS", check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default=str(EVAL / "build/andronet-eval-x64.apk"))
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--only", default="")
    ap.add_argument("--learn", type=int, default=62)
    ap.add_argument("--skip-setup", action="store_true")
    args = ap.parse_args()

    if not args.skip_setup:
        setup(args.apk)

    phone.shell(f"am force-stop {phone.EVAL_PKG}", check=False)
    time.sleep(1)
    phone.adb("logcat", "-c")
    log_path = EVAL / "results" / f"rooted_{args.tag}.logcat"
    log_file = open(log_path, "wb")
    streamer = subprocess.Popen(["adb", "logcat", "-v", "epoch", "-s", "PacketAnalysisManager:*", "NetHunterService:*", "AndroidRuntime:E"],
                                env=phone.ENV, stdout=log_file, stderr=subprocess.DEVNULL)

    phone.shell(f"am start -n {phone.MAIN} --es andronet_action start_root --es interface any")
    time.sleep(6)
    print("helper:", phone.shell("ps -A -o UID,PID,ARGS | grep -E 'capd|nc -L' | grep -v grep | cut -c1-110", check=False).strip(), flush=True)
    print(f"learning period: waiting {args.learn} s", flush=True)
    time.sleep(args.learn)

    windows = []
    only = f"--only {args.only}" if args.only else ""
    print(phone.harness(f"livegen --host {HOST} {only} --out {phone.D}/live.txt", timeout=1500)[-200:], flush=True)
    for line in phone.shell(f"cat {phone.D}/live.txt").splitlines():
        name, start, end = line.split()
        if name not in VPN_ONLY:
            windows.append((name, int(start), int(end), EXPECTED.get(name, set())))

    for name, (trace, expected) in INJECTED.items():
        if args.only and name not in args.only:
            continue
        phone.adb("push", str(EVAL / "traces/dev" / f"{trace}.pcap"), f"{phone.D}/t/{trace}.pcap")
        start = int(phone.shell("date +%s%3N").strip())
        out = phone.shell(f"{phone.D}/pcap_inject eth0 {phone.D}/t/{trace}.pcap", check=False, timeout=300)
        end = int(phone.shell("date +%s%3N").strip())
        print(name, out.strip()[-40:], flush=True)
        windows.append((name, start, end, expected))
        time.sleep(11)

    time.sleep(3)
    streamer.terminate()
    streamer.wait(5)
    log_file.close()
    alive = phone.pid_of(phone.EVAL_PKG)
    helper_uid = phone.shell("ps -A -o UID,ARGS | grep capd | grep -v grep | head -1 | cut -c1-40", check=False).strip()
    phone.shell(f"am force-stop {phone.EVAL_PKG}", check=False)
    # A process started through su must not outlive the app, even on a silent network
    time.sleep(5)
    helper_left = phone.shell("ps -A -o ARGS | grep -c '^capd'", check=False).strip()

    results, other = {}, {}
    text = log_path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        m = ALERT.match(raw)
        if not m:
            continue
        ts = int(m.group(1)) * 1000 + int(m.group(2))
        aid = alert_id(m.group(3), m.group(4))
        for name, start, end, _ in windows:
            if start <= ts <= end + 9000:
                results.setdefault(name, {}).setdefault(aid, 0)
                results[name][aid] += 1
                break
        else:
            other[aid] = other.get(aid, 0) + 1

    detected = 0
    table = []
    for name, _, _, expected in windows:
        got = results.get(name, {})
        ok = bool(expected & set(got))
        detected += ok
        table.append({"scenario": name, "detected": ok, "expected": sorted(expected), "alerts": got})
        print(f"{'OK  ' if ok else 'MISS'} {name:26s} {got}", flush=True)
    print(f"detected {detected}/{len(windows)}; other alerts: {other}; app alive: {bool(alive)}; helper: {helper_uid!r}; helpers left after stop: {helper_left}")
    (EVAL / "results" / f"rooted_{args.tag}.json").write_text(json.dumps(
        {"detected": detected, "total": len(windows), "scenarios": table, "other": other,
         "helperUidLine": helper_uid, "helpersLeftAfterStop": helper_left}, indent=1))


if __name__ == "__main__":
    main()
