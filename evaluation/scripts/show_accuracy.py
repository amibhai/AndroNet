#!/usr/bin/env python3
"""Prints one accuracy result as a per-trace table, for reading during development."""
import json
import sys


def main():
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(d["pipeline"], "thresholds=" + d["thresholds"], "view=" + d["view"])
    print(f"{'trace':38s} {'pkts':>7s} {'secs':>7s} {'flagged':>8s} {'%flag':>6s}  alerts")
    for run in d["runs"]:
        for label, v in run["labels"].items():
            n = v["packets"]
            fl = v["flagged"]["any"]
            alerts = sorted(v["alerts"].items(), key=lambda kv: -kv[1])
            text = " ".join(f"{k}={c}" for k, c in alerts[:9]) + (" ..." if len(alerts) > 9 else "")
            pct = 100.0 * fl / n if n else 0
            print(f"{run['name'][:38]:38s} {n:7d} {run['durationSec']:7.1f} {fl:8d} {pct:6.2f}  {text or '-'}")


if __name__ == "__main__":
    main()
