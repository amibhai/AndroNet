#!/usr/bin/env python3
"""A long run on a person's own phone, under normal use.

  python soak.py start --tag oppo     # then unplug and use the phone as usual
  python soak.py status --tag oppo    # with the phone plugged in again: prints the summary, changes nothing
  python soak.py collect --tag oppo   # stops the capture and writes results/soak_<tag>.json
Set ANDROID_SERIAL when more than one phone is attached.

Starting writes results/soak_<tag>_start.json before any result exists, and the paper build refuses to
finish without the matching result, so a run is reported whatever it shows. The run on the Pixel 8
began before this record existed.

The phone records one line per alert: time, finding, severity and app. No addresses, names, payloads
or captures are kept, and the log is removed from the phone once collected. The published result keeps
counts per finding and how many apps were involved. Which apps a person uses is their own business, so
the per-app counts go to results/private/, which is not published.

Coverage comes from wall-clock times. The app writes a heartbeat every 10 minutes of the phone's
awake time, and a sleeping phone stretches that interval, so heartbeats show the capture was alive
but cannot measure how long. A stretch of capture runs from its start line to its stop line, or to
now if the process that wrote the start line is still capturing; otherwise it ends at its last line.
"""
import argparse
import collections
import json
import pathlib
import re
import statistics
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]
REMOTE = "/sdcard/Download/AndroNet/andronet_soak.tsv"
HEARTBEAT_S = 600
# The process is started a moment before its service writes the start line
START_SLACK_MS = 120_000


def parse(text):
    events, alerts, heartbeats = [], [], []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        t, kind = int(fields[0]), fields[1]
        events.append((t, kind))
        if kind == "alert":
            alerts.append({"t": t, "finding": fields[2], "severity": fields[3], "app": fields[4] if len(fields) > 4 else ""})
        elif kind == "heartbeat":
            heartbeats.append({"t": t, "skipped": int(fields[2] or 0), "packets": int(fields[3] or 0) if len(fields) > 3 and fields[3] else 0})
    return events, alerts, heartbeats


def counted(heartbeats, field):
    """The counters restart with each capture, so each stretch is added at its last value."""
    total = 0
    previous = 0
    for beat in heartbeats:
        if beat[field] < previous:
            total += previous
        previous = beat[field]
    return total + previous


def device_facts():
    def prop(name):
        return phone.shell(f"getprop {name}", check=False).strip()
    return {"manufacturer": prop("ro.product.manufacturer"), "model": prop("ro.product.model"), "android": prop("ro.build.version.release")}


def installed_apk_sha256():
    paths = [line.split(":", 1)[1] for line in phone.shell(f"pm path {phone.EVAL_PKG}", check=False).split() if line.startswith("package:")]
    base = [p for p in paths if p.endswith("/base.apk")]
    out = phone.shell(f"sha256sum {base[0]}", check=False).split() if base else []
    return out[0] if out and len(out[0]) == 64 else None


def spread(alerts):
    """How each finding's alerts fall across apps, with no app named: the counts per app, largest first, and for
    a finding whose largest share is one app's repeated alert, the median hours between that app's repeats."""
    per_app = collections.defaultdict(collections.Counter)
    times = collections.defaultdict(list)
    for a in alerts:
        per_app[a["finding"]][a["app"] or "(unattributed)"] += 1
        times[(a["finding"], a["app"] or "(unattributed)")].append(a["h"])
    counts = {f: sorted(c.values(), reverse=True) for f, c in per_app.items()}
    gaps = {}
    for f, c in per_app.items():
        top, n = c.most_common(1)[0]
        if n >= 3:
            hours = sorted(times[(f, top)])
            gaps[f] = round(statistics.median(b - a for a, b in zip(hours, hours[1:])), 2)
    return {"alertsPerApp": counts, "topAppRepeatHours": gaps}


def crash_details():
    """The app's own crash reports: when, what was thrown and how long its process had run. Filtered on the
    phone, so no other app's report leaves it."""
    text = phone.shell(f"dumpsys dropbox --print data_app_crash 2>/dev/null | sed -n '/^Process: {phone.EVAL_PKG}$/,/^========/p'", check=False)
    crashes, current = [], None
    for line in text.splitlines():
        if line.startswith("Process: "):
            current = {"timestamp": None, "processRuntimeHours": None, "exception": None}
            crashes.append(current)
        elif current is None:
            continue
        elif line.startswith("Timestamp: "):
            current["timestamp"] = line.split(": ", 1)[1].strip()
        elif line.startswith("Process-Runtime: ") and line.split(": ", 1)[1].strip().isdigit():
            current["processRuntimeHours"] = round(int(line.split(": ", 1)[1]) / 3.6e6, 3)
        elif current["exception"] is None and re.match(r"^[\w.$]+(Exception|Error)\b", line):
            current["exception"] = line.strip()[:300]
    return crashes


def process_facts():
    """What the phone can say about the capture process now, with times in its own wall clock."""
    now_ms = int(phone.shell("date +%s%3N").strip())
    uptime_s = float(phone.shell("cat /proc/uptime").split()[0])
    clk = phone.shell("getconf CLK_TCK", check=False).strip()
    clk = int(clk) if clk.isdigit() else 100
    facts = {"nowMs": now_ms, "uptimeHours": round(uptime_s / 3600, 2), "tunnelUp": phone.vpn_up()}
    pid = phone.pid_of(phone.EVAL_PKG)
    if pid:
        stat = phone.shell(f"cat /proc/{pid}/stat", check=False).rsplit(")", 1)[-1].split()
        status = phone.shell(f"cat /proc/{pid}/status", check=False)
        mem = {line.split(":")[0]: int(line.split()[1]) for line in status.splitlines() if line.startswith(("VmRSS", "VmHWM"))}
        if len(stat) > 19:
            age_s = uptime_s - int(stat[19]) / clk
            cpu_s = (int(stat[11]) + int(stat[12])) / clk
            facts.update({"processStartMs": int(now_ms - age_s * 1000), "processAgeHours": round(age_s / 3600, 2),
                          "cpuSeconds": round(cpu_s), "avgCpuPct": round(100 * cpu_s / age_s, 2),
                          "rssMiB": round(mem.get("VmRSS", 0) / 1024), "peakRssMiB": round(mem.get("VmHWM", 0) / 1024)})
    # Crash reports Android keeps for the app; counted on the phone so nothing about other apps leaves it
    facts["crashReports"] = {}
    for tag in ("data_app_crash", "data_app_native_crash", "data_app_anr"):
        out = phone.shell(f"dumpsys dropbox --print {tag} 2>/dev/null | grep -c 'Process: {phone.EVAL_PKG}'", check=False).strip()
        facts["crashReports"][tag] = int(out) if out.isdigit() else None
    level = [line.split(":")[1].strip() for line in phone.shell("dumpsys battery", check=False).splitlines() if line.strip().startswith("level:")]
    facts["batteryLevel"] = int(level[0]) if level else None
    return facts


def stretches(events, facts):
    """The capture's stretches as [start, end] in ms, and whether the last one is still running."""
    spans, current, alive = [], None, False
    for t, kind in events:
        if kind == "start":
            if current:
                spans.append(current)
            current = [t, t]
        elif current:
            current[1] = max(current[1], t)
            if kind == "stop":
                spans.append(current)
                current = None
    if current:
        alive = facts["tunnelUp"] and "processStartMs" in facts and facts["processStartMs"] <= current[0] + START_SLACK_MS
        if alive:
            current[1] = facts["nowMs"]
        spans.append(current)
    return spans, alive


def save_crashes(results, tag, started_at):
    """Keeps the app's crash reports from the run, which a paper must explain before it reports the run."""
    crashes = [c for c in crash_details() if c["timestamp"] and c["timestamp"][:16] >= started_at]
    (results / f"soak_{tag}_crashes.json").write_text(json.dumps(crashes, indent=1))
    print(f"{len(crashes)} crash reports from the run kept in soak_{tag}_crashes.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["start", "status", "collect", "crashes"])
    ap.add_argument("--tag", default="pixel")
    args = ap.parse_args()

    results = EVAL / "results"
    record = results / f"soak_{args.tag}_start.json"
    device = device_facts()
    if args.action == "start":
        if (results / f"soak_{args.tag}.json").exists():
            raise SystemExit(f"a soak tagged {args.tag} is already collected; pick another tag")
        phone.shell(f"rm -f {REMOTE}", check=False)
        if not phone.start_andronet("--es soak on", guard=False):
            raise SystemExit("VPN did not come up")
        # The service writes its start line and first heartbeat as capture begins
        for _ in range(20):
            if parse(phone.shell(f"cat {REMOTE}", check=False))[0]:
                break
            time.sleep(0.5)
        else:
            phone.stop_andronet()
            raise SystemExit("capture started but its log is not being written; check the app's storage access")
        phone.home()
        record.write_text(json.dumps({"tag": args.tag, "startedAt": time.strftime("%Y-%m-%d %H:%M"), **device,
                                      "build": phone.shell("getprop ro.build.display.id", check=False).strip(),
                                      "apkSha256": installed_apk_sha256()}, indent=1))
        print(f"capture running on the {device['model']}; unplug the phone and use it normally")
        return

    if record.exists():
        began = json.loads(record.read_text())
        if began["model"] != device["model"]:
            raise SystemExit(f"the soak tagged {args.tag} started on a {began['model']}, but the attached phone is a {device['model']}; set ANDROID_SERIAL")
    if args.action == "crashes":
        # For a run collected before collect kept these
        if not record.exists():
            raise SystemExit("crashes needs the run's start record, to keep only reports from the run")
        save_crashes(results, args.tag, json.loads(record.read_text())["startedAt"])
        return
    text = phone.shell(f"cat {REMOTE}", check=False)
    events, alerts, heartbeats = parse(text)
    if not events:
        raise SystemExit("no soak log on the phone")
    facts = process_facts()
    spans, still_running = stretches(events, facts)
    first = min(t for t, kind in events if kind == "start")
    span_h = (facts["nowMs"] - first) / 3.6e6
    covered_h = sum(b - a for a, b in spans) / 3.6e6
    gaps = [b["t"] - a["t"] for a, b in zip(heartbeats, heartbeats[1:])]
    by_finding = collections.Counter(a["finding"] for a in alerts)
    by_app = collections.Counter(a["app"] or "(unattributed)" for a in alerts)
    summary = {
        "tag": args.tag, "device": device, "startedAt": time.strftime("%Y-%m-%d %H:%M", time.localtime(first / 1000)),
        "spanHours": round(span_h, 2), "coveredHours": round(covered_h, 2), "stillRunning": still_running,
        "captureStarts": sum(kind == "start" for _, kind in events), "captureStops": sum(kind == "stop" for _, kind in events),
        "rebootedDuringRun": facts["uptimeHours"] < span_h,
        # Awake time only, since the heartbeat timer stops while the phone sleeps
        "heartbeats": len(heartbeats), "heartbeatHours": round(len(heartbeats) * HEARTBEAT_S / 3600, 2),
        "longestHeartbeatGapHours": round(max(gaps) / 3.6e6, 2) if gaps else None,
        "alerts": len(alerts), "alertsPerDay": round(len(alerts) / covered_h * 24, 2) if covered_h else None,
        "byFinding": dict(by_finding.most_common()), "appsWithAlerts": len(by_app),
        "unattributedAlerts": sum(not a["app"] for a in alerts),
        "bySeverity": dict(collections.Counter(a["severity"] for a in alerts)),
        "skippedPackets": counted(heartbeats, "skipped"),
        "packets": counted(heartbeats, "packets"),
        "process": {k: facts.get(k) for k in ("processAgeHours", "cpuSeconds", "avgCpuPct", "rssMiB", "peakRssMiB")},
        "crashReports": facts["crashReports"], "uptimeHours": facts["uptimeHours"], "batteryLevelAtCollect": facts["batteryLevel"],
        **spread([{**a, "h": (a["t"] - first) / 3.6e6} for a in alerts]),
    }
    print(json.dumps(summary, indent=1))
    if args.action == "collect":
        (EVAL / "results" / f"soak_{args.tag}.json").write_text(json.dumps(summary, indent=1))
        private = EVAL / "results" / "private"
        private.mkdir(exist_ok=True)
        per_app = collections.defaultdict(collections.Counter)
        for a in alerts:
            per_app[a["app"] or "(unattributed)"][a["finding"]] += 1
        detail = {"byApp": dict(by_app.most_common()), "byAppAndFinding": {k: dict(c) for k, c in per_app.items()},
                  "alertHours": [{"h": round((a["t"] - first) / 3.6e6, 2), "finding": a["finding"], "app": a["app"]} for a in alerts]}
        (private / f"soak_{args.tag}_apps.json").write_text(json.dumps(detail, indent=1))
        if any(summary["crashReports"].values()):
            save_crashes(results, args.tag, summary["startedAt"])
        if summary["rebootedDuringRun"]:
            # Android's own word for the restart, such as "reboot,ota" for a system update
            reboot = {"tag": args.tag, "bootReason": phone.shell("getprop sys.boot.reason", check=False).strip(),
                      "buildAtCollect": phone.shell("getprop ro.build.display.id", check=False).strip(),
                      "buildAtStart": json.loads(record.read_text()).get("build") if record.exists() else None,
                      "uptimeHoursAtCollect": summary["uptimeHours"]}
            (results / f"soak_{args.tag}_reboot.json").write_text(json.dumps(reboot, indent=1))
        phone.stop_andronet()
        phone.shell(f"rm -f {REMOTE}", check=False)


if __name__ == "__main__":
    main()
