#!/usr/bin/env python3
"""Runs the accuracy replay for a named trace set, on the desktop JVM or on the attached phone.

  python run_replay.py --build baseline --set dev --where host  --thresholds shipped
  python run_replay.py --build current  --set dev --where phone --thresholds shipped
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

EVAL = pathlib.Path(__file__).resolve().parents[1]
TRACES = EVAL / "traces"
ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
PHONE_DIR = "/data/local/tmp/andronet_eval"


def stdlib_jar():
    cache = pathlib.Path.home() / ".gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.2.21"
    return str(next(cache.rglob("kotlin-stdlib-2.2.21.jar")))


def discover(which, extra_dirs):
    """name -> (path, label). Labels come from the file name prefix, fixed in fetch_traces.py."""
    items = {}
    dirs = [TRACES / which] + [pathlib.Path(d) for d in extra_dirs]
    for d in dirs:
        for p in sorted(d.glob("*")):
            if p.suffix.lower() not in (".pcap", ".pcapng", ".cap", ".gz"):
                continue
            stem = p.name.split(".")[0]
            if stem.startswith("atk_"):
                items[stem] = (p, "attack")
            elif stem.startswith("benign_"):
                items[stem] = (p, "benign")
    return items


def adb(*args, **kw):
    return subprocess.run(["adb", *args], env=ENV, check=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="baseline")
    ap.add_argument("--set", default="dev")
    ap.add_argument("--where", default="host", choices=["host", "phone"])
    ap.add_argument("--thresholds", default="shipped", choices=["shipped", "fixed"])
    ap.add_argument("--view", default="vpn")
    ap.add_argument("--only", default="", help="comma-separated name substrings")
    ap.add_argument("--skip", default="", help="comma-separated name substrings")
    ap.add_argument("--extra", action="append", default=[], help="extra directory of traces")
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    items = discover(args.set, args.extra)
    if args.only:
        wanted = args.only.split(",")
        items = {k: v for k, v in items.items() if any(w in k for w in wanted)}
    if args.skip:
        unwanted = args.skip.split(",")
        items = {k: v for k, v in items.items() if not any(w in k for w in unwanted)}
    print(len(items), "traces")
    tag = args.tag or f"{args.build}_{args.set}_{args.where}_{args.thresholds}_{args.view}"
    out = EVAL / "results" / f"accuracy_{tag}.json"
    alerts = EVAL / "results" / f"alerts_{tag}.tsv"
    build = EVAL / "build" / args.build

    if args.where == "host":
        spec = ",".join(f"{k}={p}:{lbl}" for k, (p, lbl) in items.items())
        with tempfile.NamedTemporaryFile("w", suffix=".spec", delete=False) as f:
            f.write(spec)
        cp = os.pathsep.join([str(build / "harness.jar"), str(build / "host_classes"), stdlib_jar()])
        subprocess.run(["java", "-Xmx3g", "-cp", cp, "com.andronet.eval.ReplayMainKt", "accuracy",
                        "--specfile", f.name, "--thresholds", args.thresholds, "--view", args.view,
                        "--out", str(out), "--alerts", str(alerts)], check=True)
        os.unlink(f.name)
    else:
        adb("shell", f"mkdir -p {PHONE_DIR}/t")
        adb("push", str(build / "harness.dex"), f"{PHONE_DIR}/{args.build}.dex", stdout=subprocess.DEVNULL)
        for k, (p, lbl) in items.items():
            adb("push", str(p), f"{PHONE_DIR}/t/{p.name}", stdout=subprocess.DEVNULL)
        spec = ",".join(f"{k}={PHONE_DIR}/t/{p.name}:{lbl}" for k, (p, lbl) in items.items())
        specfile = pathlib.Path(tempfile.gettempdir()) / "andronet.spec"
        specfile.write_text(spec)
        adb("push", str(specfile), f"{PHONE_DIR}/spec.txt", stdout=subprocess.DEVNULL)
        adb("shell", f"CLASSPATH={PHONE_DIR}/{args.build}.dex app_process / com.andronet.eval.ReplayMainKt accuracy "
                     f"--specfile {PHONE_DIR}/spec.txt --thresholds {args.thresholds} --view {args.view} "
                     f"--out {PHONE_DIR}/acc.json --alerts {PHONE_DIR}/alerts.tsv")
        adb("pull", f"{PHONE_DIR}/acc.json", str(out), stdout=subprocess.DEVNULL)
        adb("pull", f"{PHONE_DIR}/alerts.tsv", str(alerts), stdout=subprocess.DEVNULL)
        adb("shell", f"rm -rf {PHONE_DIR}/t {PHONE_DIR}/acc.json {PHONE_DIR}/alerts.tsv")
    print("wrote", out)


if __name__ == "__main__":
    main()
