#!/usr/bin/env python3
"""Measures per-stage pipeline cost on the attached phone under ART.

  python run_cost.py --build baseline --trace traces/dev/benign_smallFlows.pcap --cpus f0 --tag mid

--cpus is a taskset hex mask. On Tensor G3: 0f = Cortex-A510 (little), f0 = Cortex-A715 (mid),
100 = Cortex-X3 (big). Without it the scheduler places the process, as it would for an app.
"""
import argparse
import json
import os
import pathlib
import subprocess

EVAL = pathlib.Path(__file__).resolve().parents[1]
ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
D = "/data/local/tmp/andronet_eval"


def adb(*args, **kw):
    return subprocess.run(["adb", *args], env=ENV, check=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="current")
    ap.add_argument("--trace", required=True)
    ap.add_argument("--limit", default="20000")
    ap.add_argument("--repeat", default="3")
    ap.add_argument("--cpus", default="")
    ap.add_argument("--tag", default="sched")
    ap.add_argument("--thresholds", default="fixed")
    args = ap.parse_args()

    trace = pathlib.Path(args.trace)
    adb("shell", f"mkdir -p {D}/t")
    adb("push", str(EVAL / "build" / args.build / "harness.dex"), f"{D}/{args.build}.dex", stdout=subprocess.DEVNULL)
    adb("push", str(trace), f"{D}/t/{trace.name}", stdout=subprocess.DEVNULL)
    prefix = f"taskset {args.cpus} " if args.cpus else ""
    out = f"{D}/cost.json"
    cmd = (f"cd {D} && CLASSPATH={D}/{args.build}.dex {prefix}app_process / com.andronet.eval.ReplayMainKt cost "
           f"--trace {D}/t/{trace.name} --limit {args.limit} --repeat {args.repeat} --thresholds {args.thresholds} --out {out}")
    adb("shell", cmd)
    dest = EVAL / "results" / f"cost_{args.build}_{trace.stem}_{args.tag}.json"
    adb("pull", out, str(dest), stdout=subprocess.DEVNULL)
    r = json.loads(dest.read_text())
    s = r["stages"]
    l1 = s["noRulesNoSigs.detect"]["meanUs"]
    l2 = s["noRules.detect"]["meanUs"] - l1
    l3 = s["full.detect"]["meanUs"] - s["noRules.detect"]["meanUs"]
    print(f"{args.build} {trace.name} {args.tag}: n={r['packets']} parse={s['full.parse']['meanUs']:.1f} stats={s['full.stats']['meanUs']:.1f} "
          f"dpi={s['full.dpi']['meanUs']:.1f} L1={l1:.1f} L2={l2:.1f} L3={l3:.1f} us | total mean={s['full.total']['meanUs']:.1f} "
          f"p50={s['full.total']['p50Us']:.1f} p95={s['full.total']['p95Us']:.1f} p99={s['full.total']['p99Us']:.1f} us | "
          f"best={s['full.wall']['bestPps']:.0f} pps | heapDelta={r['heap']['deltaBytes'] / 1024:.0f} KiB")


if __name__ == "__main__":
    main()
