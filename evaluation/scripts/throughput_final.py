#!/usr/bin/env python3
"""Head-to-head capture overhead on the phone: no capture, PCAPdroid, and AndroNet in three modes.

Conditions run in a freshly shuffled order each round, so Wi-Fi drift over time is not confounded
with any one condition. All transfers run between the phone and the lab host on the same Wi-Fi.

  python throughput_final.py --rounds 5 --mb 50
  python throughput_final.py --rounds 4 --mb 50 --resume   # adds rounds to the saved results

Results are saved after every condition. An app_process killed mid-measurement (rc=137, seen rarely
and not explained) or a capture that fails to start is logged and counted in the _meta file, so a
gap in the data stays visible.
"""
import argparse
import json
import pathlib
import random
import re
import statistics
import subprocess
import threading
import time

import phone
import ui

EVAL = pathlib.Path(__file__).resolve().parents[1]
HOST = "192.168.1.8"
PD = phone.PCAPDROID


def start_pcapdroid(dump):
    phone.shell(f"am start -e action start -e pcap_dump_mode {dump} -e pcap_name eval.pcap -n {PD}/.activities.CaptureCtrl")
    ui.tap_text("ALLOW", timeout=6)
    for _ in range(20):
        time.sleep(0.5)
        if phone.vpn_up():
            return True
    return False


def stop_pcapdroid():
    phone.shell(f"am force-stop {PD}", check=False)
    for _ in range(20):
        time.sleep(0.5)
        if not phone.vpn_up():
            return


CONDITIONS = {
    "no_capture": (None, None, None),
    "pcapdroid": (lambda: start_pcapdroid("none"), stop_pcapdroid, PD),
    "pcapdroid_pcap_file": (lambda: start_pcapdroid("pcap_file"), stop_pcapdroid, PD),
    "andronet_forward": (lambda: phone.start_andronet("--es analysis off --es ui off"), phone.stop_andronet, phone.EVAL_PKG),
    "andronet_analysis": (lambda: phone.start_andronet("--es ui off"), phone.stop_andronet, phone.EVAL_PKG),
    "andronet_full": (lambda: phone.start_andronet(""), phone.stop_andronet, phone.EVAL_PKG),
}


def rates(direction, mb, repeat):
    out = phone.shell(f"CLASSPATH={phone.D}/current.dex app_process / com.andronet.eval.ReplayMainKt transfer "
                      f"--host {HOST} --direction {direction} --mb {mb} --repeat {repeat}; echo rc=$?", check=False, timeout=600)
    values = [float(x) for x in re.findall(r"([\d.]+) Mbit/s", out)]
    if "rc=0" not in out:
        print("   problem:", out.strip()[-140:], flush=True)
    return values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--mb", type=int, default=50)
    ap.add_argument("--only", default="")
    ap.add_argument("--tag", default="final")
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    phone.push_harness()
    phone.shell(f"am force-stop {phone.EVAL_PKG}; am force-stop {PD}", check=False)
    results = {name: {"down": [], "up": [], "cpu": [], "rss": [], "rttP50": [], "rttP95": []} for name in CONDITIONS}
    meta = {"rounds": 0, "failedStarts": {}, "killedDuringRtt": 0, "interrupted": {}}
    out_path = EVAL / "results" / f"throughput_{args.tag}.json"
    meta_path = EVAL / "results" / f"throughput_{args.tag}_meta.json"
    if args.resume:
        results = json.loads(out_path.read_text())
        meta = json.loads(meta_path.read_text())
        meta.setdefault("interrupted", {})
    names = [n for n in CONDITIONS if not args.only or n in args.only.split(",")]
    rng = random.Random(20261102 + meta["rounds"])

    def save():
        out_path.write_text(json.dumps(results, indent=1))
        meta_path.write_text(json.dumps(meta, indent=1))

    def environment():
        """Temperature and link speed, logged per condition, so that drift over a run can be explained."""
        battery = phone.shell("dumpsys battery | grep temperature", check=False)
        wifi = phone.shell("dumpsys wifi | grep -m1 'Link speed'", check=False)
        t = re.search(r"temperature: (\d+)", battery)
        speed = re.search(r"Link speed: (\d+)", wifi)
        rssi = re.search(r"RSSI: (-?\d+)", wifi)
        return {"tempC": int(t.group(1)) / 10 if t else None, "linkMbps": int(speed.group(1)) if speed else None,
                "rssi": int(rssi.group(1)) if rssi else None}

    def measure(name, round_no):
        start, stop, pkg = CONDITIONS[name]
        if start and not start():
            print(name, "capture did not start; retrying once", flush=True)
            meta["failedStarts"][name] = meta["failedStarts"].get(name, 0) + 1
            stop()
            time.sleep(2)
            if not start():
                print(name, "capture did not start twice; skipping this round", flush=True)
                stop()
                return
        phone.home()
        time.sleep(2)
        pid = phone.pid_of(pkg) if pkg else None
        j0 = phone.proc_jiffies(pid) if pid else 0
        t0 = time.time()
        peak = [0]
        done = threading.Event()

        def watch():
            while pid and not done.wait(1.5):
                try:
                    peak[0] = max(peak[0], phone.rss_kib(pid))
                except Exception:
                    pass

        threading.Thread(target=watch, daemon=True).start()
        down = rates("down", args.mb, 2)
        up = rates("up", args.mb, 2)
        busy_secs = time.time() - t0
        done.set()
        cpu = (phone.proc_jiffies(pid) - j0) / 100.0 / busy_secs * 100 if pid else 0.0
        try:
            rtt = phone.harness(f"rtt --host {HOST} --samples 30", timeout=120)
        except subprocess.CalledProcessError as e:
            print("   rtt run ended with", e.returncode, flush=True)
            meta["killedDuringRtt"] += 1
            rtt = ""
        m = re.search(r"p50=([\d.]+) p95=([\d.]+)", rtt)
        env = environment()
        if stop:
            stop()
        # Only a condition that ran to the end counts, so a USB drop cannot leave half a sample
        r = results[name]
        r["down"] += down
        r["up"] += up
        if pid:
            r["cpu"].append(round(cpu, 1))
            r["rss"].append(peak[0] // 1024)
        if m:
            r["rttP50"].append(float(m.group(1)))
            r["rttP95"].append(float(m.group(2)))
        print(f"[{round_no + 1}/{args.rounds}] {name:20s} down={down} up={up} cpu={cpu:.0f}% rss={peak[0] // 1024} rtt={m.group(1) if m else '?'} ms {env}", flush=True)
        save()

    for round_no in range(args.rounds):
        order = names[:]
        rng.shuffle(order)
        for name in order:
            for attempt in range(3):
                try:
                    measure(name, round_no)
                    break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                    print(f"{name}: interrupted ({str(e)[:90]}); waiting for the phone", flush=True)
                    meta["interrupted"][name] = meta["interrupted"].get(name, 0) + 1
                    subprocess.run(["adb", "wait-for-device"], env=phone.ENV, timeout=3600, check=False)
                    time.sleep(10)
                    phone.shell(f"am force-stop {phone.EVAL_PKG}; am force-stop {PD}", check=False)
                    time.sleep(3)
            time.sleep(2)
        meta["rounds"] += 1
        save()

    print("\nmedians")
    for name in names:
        r = results[name]
        med = lambda v: statistics.median(v) if v else 0  # noqa: E731
        print(f"{name:20s} down={med(r['down']):6.1f} up={med(r['up']):6.1f} Mbit/s cpu={med(r['cpu']):5.1f}% rss={med(r['rss']):5.0f} MiB rtt={med(r['rttP50']):5.1f} ms")
    phone.shell("rm -f /sdcard/Download/PCAPdroid/eval.pcap", check=False)


if __name__ == "__main__":
    main()
