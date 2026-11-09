#!/usr/bin/env python3
"""A yardstick for the fresh set: Suricata with the ET Open rules, on the desktop, over the same captures.

Applies the same reading as flow_check.py: an alert counts as detecting a capture only if the packet flow
it names belongs to the attack. Suricata's expected alerts were not written down in advance, so any alert
on the attack's flows counts, which is generous to it, and the signature names are kept so that a reader
can judge them. Its rules date from years after these captures, which is generous as well.

  python suricata_baseline.py <suricata dir> <rules dir>
"""
import collections
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

from flow_check import CONTROLLERS, FRESH, packets
from test_manifest_v2 import ATTACKS

EVAL = pathlib.Path(__file__).resolve().parents[1]
SESSIONS = EVAL / "results" / "private" / "second_cycle"
PAUSE_FILE = EVAL / "results" / "throughput_running.txt"


def run_one(exe, config, rules, path):
    while PAUSE_FILE.exists():  # the laptop has to stay idle while it serves the throughput runs
        time.sleep(30)
    with tempfile.TemporaryDirectory() as out:
        cmd = [str(exe), "-c", str(config), "-r", str(path), "-l", out, "-k", "none", "--runmode", "single", "-S", str(rules),
               "--set", "vars.address-groups.HOME_NET=any", "--set", "vars.address-groups.EXTERNAL_NET=any",
               "--set", f"classification-file={rules.parent / 'classification.config'}",
               "--set", f"reference-config-file={exe.parent / 'reference.config'}"]
        # Npcap's folder holds wpcap.dll, which Suricata's Windows build needs even to read a file
        env = dict(os.environ, PATH="C:\\Windows\\System32\\Npcap;" + os.environ["PATH"])
        run = subprocess.run(cmd, capture_output=True, text=True, errors="replace", cwd=str(exe.parent), env=env)
        eve = pathlib.Path(out) / "eve.json"
        alerts = []
        if eve.exists():
            for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    a = event["alert"]
                    alerts.append({"signature": a["signature"], "category": a.get("category", ""), "severity": a.get("severity"),
                                   "src": event.get("src_ip"), "dst": event.get("dest_ip"),
                                   "sport": str(event.get("src_port", "")), "dport": str(event.get("dest_port", ""))})
        if not eve.exists() and run.returncode:
            raise SystemExit(f"suricata failed on {path.name}: {run.stderr[-500:]}{run.stdout[-500:]}")
    return path.stem.split(".")[0], alerts


def on_attack(name, alert, target):
    if name in CONTROLLERS:
        address, port = CONTROLLERS[name]
        ok_address = address is None or address in (alert["src"], alert["dst"])
        ok_port = port is None or str(port) in (alert["sport"], alert["dport"])
        return ok_address and ok_port
    return target in (alert["src"], alert["dst"])


def main():
    root = pathlib.Path(sys.argv[1])
    exe = next(root.rglob("suricata.exe"))
    config = next(root.rglob("suricata.yaml"))
    rules_dir = pathlib.Path(sys.argv[2])
    combined = rules_dir / "all_for_baseline.rules"
    with open(combined, "w", encoding="utf-8") as out:
        for f in sorted(rules_dir.glob("*.rules")):
            if f.name not in ("all_for_baseline.rules", "deleted.rules"):
                out.write(f.read_text(encoding="utf-8", errors="replace"))

    captures = sorted(FRESH.glob("*")) + sorted(SESSIONS.glob("benign_*.pcapng"))
    results = {}
    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        for name, alerts in pool.map(lambda p: run_one(exe, config, combined, p), captures):
            results[name] = alerts
            print(name, len(alerts), flush=True)

    version = subprocess.run([str(exe), "-V"], capture_output=True, text=True, errors="replace", cwd=str(exe.parent),
                             env=dict(os.environ, PATH="C:\\Windows\\System32\\Npcap;" + os.environ["PATH"])).stdout.strip()
    summary = {"suricata": version, "rules": sum(1 for line in combined.read_text(encoding="utf-8", errors="replace").splitlines() if line.startswith("alert")),
               "rulesDownloaded": time.strftime("%Y-%m-%d", time.localtime((rules_dir / "emerging-malware.rules").stat().st_mtime)),
               "captures": {}}
    for name, alerts in results.items():
        meta = ATTACKS.get(name)
        row = {"alerts": len(alerts), "signatures": dict(collections.Counter(a["signature"] for a in alerts).most_common())}
        if meta and meta["expect"]:
            target = ""
            if alerts and name not in CONTROLLERS:
                _, busiest = packets(next(FRESH.glob(f"{name}.*")))
                target = busiest.most_common(1)[0][0] if busiest else ""
            hits = [a for a in alerts if on_attack(name, a, target)]
            row.update({"class": meta["class"], "scoped": True, "anywhere": bool(alerts), "onAttack": len(hits),
                        "onAttackSignatures": dict(collections.Counter(a["signature"] for a in hits).most_common())})
        summary["captures"][name] = row
    scoped = {k: v for k, v in summary["captures"].items() if v.get("scoped")}
    summary["recallOnAttack"] = sum(bool(v["onAttack"]) for v in scoped.values())
    summary["recallAnywhere"] = sum(v["anywhere"] for v in scoped.values())
    summary["scoped"] = len(scoped)
    summary["byClass"] = {}
    for v in scoped.values():
        c = summary["byClass"].setdefault(v["class"], {"onAttack": 0, "total": 0})
        c["onAttack"] += bool(v["onAttack"])
        c["total"] += 1
    summary["benignAlerts"] = {k: v["alerts"] for k, v in summary["captures"].items() if k.startswith("benign_")}
    (EVAL / "results" / "suricata_baseline.json").write_text(json.dumps(summary, indent=1))
    print("recall on attack flows", summary["recallOnAttack"], "of", summary["scoped"], "anywhere", summary["recallAnywhere"], summary["byClass"])
    print("benign", summary["benignAlerts"])


if __name__ == "__main__":
    main()
