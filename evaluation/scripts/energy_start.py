#!/usr/bin/env python3
"""Prepares the phone for the battery measurement and starts it, then later collects the results.

  python energy_start.py dry     # checks the whole sequence with the cable in, in about 3 minutes
  python energy_start.py start   # then pull the USB cable when told to
  python energy_start.py collect # after plugging back in: restores settings and scores the runs

Settings changed for the run, and restored by `collect`: screen stays on at minimum brightness so
the phone cannot suspend mid-run (the display draw is common to all conditions), and Doze is off.
"""
import csv
import json
import pathlib
import statistics
import subprocess
import sys

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]
SAVED = EVAL / "results" / "energy_saved_settings.json"
HOST = "192.168.1.8"


def start():
    saved = {
        "brightness": phone.shell("settings get system screen_brightness").strip(),
        "mode": phone.shell("settings get system screen_brightness_mode").strip(),
        "timeout": phone.shell("settings get system screen_off_timeout").strip(),
    }
    SAVED.write_text(json.dumps(saved))
    phone.shell("settings put system screen_brightness_mode 0; settings put system screen_brightness 1; "
                "settings put system screen_off_timeout 86400000; dumpsys deviceidle disable >/dev/null")
    phone.shell("svc power stayon true; input keyevent KEYCODE_WAKEUP; input keyevent KEYCODE_HOME")
    phone.adb("push", str(EVAL / "lab/energy.sh"), f"{phone.D}/energy.sh")
    phone.shell(f"rm -f {phone.D}/energy_done {phone.D}/energy_samples.csv {phone.D}/energy_runs.csv {phone.D}/energy.log; chmod 755 {phone.D}/energy.sh")
    subprocess.Popen(["adb", "shell", f"cd {phone.D} && setsid nohup sh energy.sh {HOST} 150 10 > energy.log 2>&1 < /dev/null &"],
                     env=phone.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("started; the script waits for the USB cable to be removed")


def dry():
    phone.adb("push", str(EVAL / "lab/energy.sh"), f"{phone.D}/energy.sh")
    phone.shell(f"rm -f {phone.D}/energy_done {phone.D}/energy_samples.csv {phone.D}/energy_runs.csv; chmod 755 {phone.D}/energy.sh")
    phone.shell(f"cd {phone.D} && sh energy.sh {HOST} 5 10 dry", timeout=400)
    print(phone.shell(f"cat {phone.D}/energy_runs.csv"))
    print(phone.shell(f"wc -l {phone.D}/energy_samples.csv; tail -2 {phone.D}/energy_samples.csv"))


def collect():
    print(phone.shell(f"tail -3 {phone.D}/energy.log", check=False))
    done = "done" in phone.shell(f"cat {phone.D}/energy_done 2>/dev/null", check=False)
    print("finished:", done)
    private = EVAL / "results"
    phone.adb("pull", f"{phone.D}/energy_samples.csv", str(private / "energy_samples.csv"))
    phone.adb("pull", f"{phone.D}/energy_runs.csv", str(private / "energy_runs.csv"))

    # Restore the phone
    if SAVED.exists():
        s = json.loads(SAVED.read_text())
        phone.shell(f"settings put system screen_brightness {s['brightness']}; settings put system screen_brightness_mode {s['mode']}; "
                    f"settings put system screen_off_timeout {s['timeout']}")
    phone.shell("svc power stayon false; dumpsys deviceidle enable >/dev/null", check=False)

    samples = {}
    with open(private / "energy_samples.csv") as f:
        for row in csv.DictReader(f):
            key = (row["cond"], row["work"], row["rep"])
            # current_now is negative while discharging on this device
            samples.setdefault(key, []).append(-int(row["current_ua"]) / 1e6 * int(row["voltage_uv"]) / 1e6)
    runs = {}
    with open(private / "energy_runs.csv") as f:
        for row in csv.DictReader(f):
            runs[(row["cond"], row["work"], row["rep"])] = row

    table = {}
    for key, watts in sorted(samples.items()):
        r = runs.get(key)
        if not r:
            continue
        seconds = (int(r["t1_ms"]) - int(r["t0_ms"])) / 1000
        charge = (int(r["charge0_uah"]) - int(r["charge1_uah"])) / 1000
        cpu = (int(r["jiffies1"]) - int(r["jiffies0"])) / 100 / seconds * 100
        entry = {"meanW": statistics.mean(watts), "n": len(watts), "seconds": seconds, "chargeMah": charge,
                 "cpuPct": cpu, "tun": int(r["tun"]), "plugged": int(r["plugged"]), "tempC": int(r["temp_decic"]) / 10}
        table.setdefault(key[1], {}).setdefault(key[0], []).append(entry)
        print(f"{key[1]:8s} {key[0]:10s} rep{key[2]} mean={entry['meanW']:.3f} W charge={charge:.1f} mAh in {seconds:.0f} s cpu={cpu:.1f}% tun={r['tun']} plugged={r['plugged']} temp={entry['tempC']}")

    capacity = int(phone.shell("cat /sys/class/power_supply/battery/charge_full").strip()) / 1000
    summary = {"capacityMah": capacity, "work": {}, "excludedRuns": []}
    for work, conds in table.items():
        for cond, all_entries in conds.items():
            # A cable reconnected during a run makes the gauge read charging, so the run says nothing
            entries = [e for e in all_entries if not e["plugged"]]
            summary["excludedRuns"] += [f"{cond} {work}"] * (len(all_entries) - len(entries))
            w = [e["meanW"] for e in entries]
            mah = [e["chargeMah"] / e["seconds"] * 3600 for e in entries]
            summary["work"].setdefault(work, {})[cond] = {
                "meanW": statistics.mean(w), "stdevW": statistics.stdev(w) if len(w) > 1 else 0,
                "mahPerHour": statistics.mean(mah), "pctPerHour": statistics.mean(mah) / capacity * 100,
                "cpuPct": statistics.mean(e["cpuPct"] for e in entries), "runs": len(entries),
                "pluggedRuns": len(all_entries) - len(entries)}
    (private / "energy_summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    {"start": start, "collect": collect, "dry": dry}[sys.argv[1]]()
