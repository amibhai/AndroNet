#!/usr/bin/env python3
"""Runs the accuracy replay for a named trace set, on the desktop JVM or on the attached phone.

  python run_replay.py --build baseline --set dev --where host  --thresholds shipped
  python run_replay.py --build current  --set dev --where phone --thresholds shipped
"""
import argparse
import os
import pathlib
import subprocess
import tempfile
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]
TRACES = EVAL / "traces"
PHONE_DIR = "/data/local/tmp/andronet_eval"


def stdlib_jar():
    cache = pathlib.Path.home() / ".gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.2.21"
    return str(next(cache.rglob("kotlin-stdlib-2.2.21.jar")))


def discover(which, extra_dirs):
    """name -> (path, label). Labels come from the file name prefix, fixed in fetch_traces.py."""
    items = {}
    # A set may come entirely from extra folders, as the second cycle's does. A named extra folder that
    # is not there would drop its traces without a word; on Windows a path such as /d/x resolves to
    # C:\d\x, so write D:/x.
    absent = [d for d in extra_dirs if not pathlib.Path(d).is_dir()]
    if absent:
        raise SystemExit(f"no such trace folder: {absent}")
    dirs = [d for d in [TRACES / which] if d.is_dir()] + [pathlib.Path(d) for d in extra_dirs]
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
        phone.shell(f"mkdir -p {PHONE_DIR}/t; rm -f {PHONE_DIR}/replay_done")
        phone.adb("push", str(build / "harness.dex"), f"{PHONE_DIR}/{args.build}.dex")
        for k, (p, lbl) in items.items():
            phone.adb("push", str(p), f"{PHONE_DIR}/t/{p.name}")
        spec = ",".join(f"{k}={PHONE_DIR}/t/{p.name}:{lbl}" for k, (p, lbl) in items.items())
        specfile = pathlib.Path(tempfile.gettempdir()) / "andronet.spec"
        specfile.write_text(spec)
        phone.adb("push", str(specfile), f"{PHONE_DIR}/spec.txt")
        # Detached from this shell, so a dropped cable costs a wait and does not end a long replay
        phone.shell(f"nohup sh -c 'CLASSPATH={PHONE_DIR}/{args.build}.dex app_process / com.andronet.eval.ReplayMainKt accuracy "
                    f"--specfile {PHONE_DIR}/spec.txt --thresholds {args.thresholds} --view {args.view} "
                    f"--out {PHONE_DIR}/acc.json --alerts {PHONE_DIR}/alerts.tsv; echo $? > {PHONE_DIR}/replay_done' "
                    f"> {PHONE_DIR}/replay.log 2>&1 &")
        while True:
            time.sleep(10)
            done = phone.shell(f"cat {PHONE_DIR}/replay_done 2>/dev/null", check=False).strip()
            if done:
                break
        if done != "0":
            print(phone.shell(f"tail -n 20 {PHONE_DIR}/replay.log", check=False))
            raise SystemExit(f"replay ended with {done}")
        phone.adb("pull", f"{PHONE_DIR}/acc.json", str(out))
        phone.adb("pull", f"{PHONE_DIR}/alerts.tsv", str(alerts))
        phone.shell(f"rm -rf {PHONE_DIR}/t {PHONE_DIR}/acc.json {PHONE_DIR}/alerts.tsv {PHONE_DIR}/replay_done {PHONE_DIR}/replay.log")
    print("wrote", out)


if __name__ == "__main__":
    main()
