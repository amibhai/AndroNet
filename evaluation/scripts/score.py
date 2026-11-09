#!/usr/bin/env python3
"""Scores accuracy results against the held-out ground truth.

  python score.py results/accuracy_baseline_test_phone_shipped_vpn.json results/accuracy_current_test_phone_shipped_root.json

Definitions, also stated in the paper:
  capture recall   in-scope attack captures with at least one alert from their expected set,
                   divided by all in-scope attack captures
  false alarm rate alerts raised on benign traffic per 1000 benign packets, and per hour of capture
  packet FPR       benign packets that raised any alert, divided by benign packets
  alert precision  alerts on attack traffic, divided by all alerts, in the mixed replay
"""
import json
import pathlib
import sys

from test_manifest import ATTACKS, BENIGN


def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def layer_of(alert):
    return "L1" if alert.startswith("L1:") else "L3" if alert.startswith("RULE-") else "L2"


def per_trace(result):
    """name -> (packets, flagged dict, alerts dict, seconds)"""
    out = {}
    for run in result["runs"]:
        for label, v in run["labels"].items():
            out[run["name"]] = (v["packets"], v["flagged"], v["alerts"], run["durationSec"])
        if not run["labels"]:
            out[run["name"]] = (0, {"any": 0, "L1": 0, "L2": 0, "L3": 0}, {}, run["durationSec"])
    return out


def score(result):
    traces = per_trace(result)
    summary = {"pipeline": result["pipeline"], "thresholds": result["thresholds"], "view": result["view"]}

    scoped = {k: v for k, v in ATTACKS.items() if v["expect"]}
    rows = {}
    detected = 0
    by_layer = {"L1": 0, "L2": 0, "L3": 0}
    scoped_present = 0
    for name, meta in scoped.items():
        if name not in traces:
            continue
        scoped_present += 1
        alerts = traces[name][2]
        hits = sorted(set(alerts) & set(meta["expect"]))
        detected += bool(hits)
        for layer in by_layer:
            by_layer[layer] += any(layer_of(a) == layer for a in hits)
        rows[name] = {"class": meta["class"], "detected": bool(hits), "hits": hits, "alerts": alerts, "packets": traces[name][0]}
    summary["recall"] = {"detected": detected, "total": scoped_present, "byLayer": by_layer}

    untargeted = {k: traces[k] for k, v in ATTACKS.items() if not v["expect"] and k in traces}
    summary["untargeted"] = {k: {"alerts": v[2], "packets": v[0]} for k, v in untargeted.items()}

    benign = {k: v for k, v in traces.items() if k.startswith("benign_")}
    packets = sum(v[0] for v in benign.values())
    flagged = sum(v[1]["any"] for v in benign.values())
    seconds = sum(v[3] for v in benign.values())
    alerts_total = {}
    per_benign = {}
    for k, v in benign.items():
        per_benign[k] = {"packets": v[0], "flagged": v[1]["any"], "alerts": v[2], "seconds": v[3]}
        for a, n in v[2].items():
            alerts_total[a] = alerts_total.get(a, 0) + n
    n_alerts = sum(alerts_total.values())
    layer_alerts = {"L1": 0, "L2": 0, "L3": 0}
    for a, n in alerts_total.items():
        layer_alerts[layer_of(a)] += n
    summary["benign"] = {
        "packets": packets, "flaggedPackets": flagged, "packetFPR": flagged / packets if packets else 0,
        "alerts": n_alerts, "alertsPer1000": 1000 * n_alerts / packets if packets else 0,
        "seconds": seconds, "alertsPerHour": 3600 * n_alerts / seconds if seconds else 0,
        "byAlert": alerts_total, "byLayer": layer_alerts, "perTrace": per_benign,
    }
    summary["captures"] = rows
    return summary


def show(s):
    print(f"\n=== {s['pipeline']} thresholds={s['thresholds']} view={s['view']}")
    r = s["recall"]
    print(f"capture recall {r['detected']}/{r['total']}  by layer {r['byLayer']}")
    for name, row in s["captures"].items():
        mark = "OK  " if row["detected"] else "MISS"
        print(f"  {mark} {name:34s} {row['class']:22s} pkts={row['packets']:<7d} {row['alerts']}")
    print("  untargeted:")
    for name, row in s["untargeted"].items():
        print(f"       {name:34s} pkts={row['packets']:<7d} {row['alerts']}")
    b = s["benign"]
    print(f"benign packets={b['packets']} flagged={b['flaggedPackets']} ({100 * b['packetFPR']:.3f}%) alerts={b['alerts']} "
          f"({b['alertsPer1000']:.3f}/1000 pkts, {b['alertsPerHour']:.1f}/h of capture) by layer {b['byLayer']}")
    for name, row in b["perTrace"].items():
        pct = 100 * row["flagged"] / row["packets"] if row["packets"] else 0
        print(f"       {name:30s} pkts={row['packets']:<8d} secs={row['seconds']:<8.1f} flagged={row['flagged']:<7d} ({pct:6.2f}%) {row['alerts']}")


def main():
    out = {}
    for path in sys.argv[1:]:
        s = score(load(path))
        show(s)
        out[pathlib.Path(path).stem] = s
    target = pathlib.Path(__file__).resolve().parents[1] / "results" / "scored.json"
    existing = json.loads(target.read_text()) if target.exists() else {}
    existing.update(out)
    target.write_text(json.dumps(existing, indent=1))


if __name__ == "__main__":
    main()
