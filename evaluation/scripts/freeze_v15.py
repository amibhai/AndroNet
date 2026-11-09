#!/usr/bin/env python3
"""Records what was frozen before the second held-out replay: every source that can change a verdict
or a measurement, the ground truth, the fresh captures' hashes, and the builds under test.

  python freeze_v15.py          # writes results/freeze_v15.json, and refuses to overwrite it
  python freeze_v15.py --check  # exits non-zero if anything has changed since the freeze
  python freeze_v15.py --amend "why"  # records a change after the freeze, leaving the frozen record as it was

An amendment says what changed and why, with new hashes. The frozen hashes stay, and so do the frozen
builds, so the first results can still be reproduced and told apart from anything measured later.
"""
import datetime
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVAL = ROOT / "evaluation"
KT = ROOT / "android/app/src/main/kotlin/com/example/packet_analyzer"
OUT = EVAL / "results" / "freeze_v15.json"

SOURCES = sorted(p for p in KT.glob("*.kt")) + [
    ROOT / "android/app/src/main/jni/zdtun_vpn.c",
    ROOT / "android/app/src/main/jni/capture_helper.c",
    ROOT / "android/app/src/main/zdtun/zdtun.c",
    ROOT / "android/app/CMakeLists.txt",
    ROOT / "android/app/src/main/AndroidManifest.xml",
    EVAL / "scripts/test_manifest_v2.py",
    EVAL / "scripts/score.py",
    EVAL / "harness/src/com/andronet/eval/ReplayMain.kt",
    EVAL / "harness/pipeline_current/CurrentPipeline.kt",
]
BUILDS = [EVAL / "build/current/harness.dex", EVAL / "build/current/harness.jar", EVAL / "build/v140/harness.dex",
          EVAL / "build/andronet-eval-arm64.apk", EVAL / "build/andronet-eval-x64.apk",
          EVAL / "build/v151/harness.dex", EVAL / "build/v151/harness.jar",
          EVAL / "build/andronet-eval-arm64-v151.apk", EVAL / "build/andronet-eval-x64-v151.apk",
          EVAL / "build/andronet-eval-arm64-v152.apk"]


def text_hash(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def snapshot():
    return {
        "sources": {str(p.relative_to(ROOT)).replace("\\", "/"): text_hash(p) for p in SOURCES},
        "builds": {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in BUILDS if p.exists()},
        "freshSet": json.loads((EVAL / "results/fresh_set.json").read_text()),
    }


def recorded(frozen):
    """The freeze with its amendments applied."""
    state = {part: dict(frozen[part]) for part in ("sources", "builds")}
    for amendment in frozen["amendments"]:
        for part in state:
            state[part].update(amendment[part])
    return state


def changes(frozen, now):
    state = recorded(frozen)
    return {part: {k: v for k, v in now[part].items() if state[part].get(k) != v} for part in state}


def main():
    if "--check" in sys.argv:
        frozen = json.loads(OUT.read_text())
        changed = [k for part in changes(frozen, snapshot()).values() for k in part]
        print("changed since the freeze and its amendments:" if changed else "matches the freeze and its amendments", changed or "")
        raise SystemExit(1 if changed else 0)
    if "--amend" in sys.argv:
        frozen = json.loads(OUT.read_text())
        delta = changes(frozen, snapshot())
        frozen["amendments"].append({"date": datetime.date.today().isoformat(), "why": sys.argv[sys.argv.index("--amend") + 1], **delta})
        OUT.write_text(json.dumps(frozen, indent=1))
        print("recorded:", [k for part in delta.values() for k in part])
        return
    if OUT.exists():
        raise SystemExit("already frozen; a change needs a recorded amendment, not a new freeze")
    OUT.write_text(json.dumps({**snapshot(), "amendments": []}, indent=1))
    print("frozen:", OUT)


if __name__ == "__main__":
    main()
