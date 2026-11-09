#!/usr/bin/env python3
"""Swaps the replay of the whole held-out phone session into the saved held-out results.

The first run of benign_session.py kept only the session's first rotated capture (110 s of 523 s),
so the held-out results covered part of that session. This replaces that one trace, in each result
file, by a replay of the merged capture. The other traces are deterministic and stay as they ran.
"""
import json
import pathlib

RESULTS = pathlib.Path(__file__).resolve().parents[1] / "results"
TRACE = "benign_phone_test_00"
PAIRS = {"current_test_phone": "current_session_phone",
         "current_test_host": "current_session_host",
         "baseline_test_host": "baseline_session_host"}


def main():
    for target, replay in PAIRS.items():
        whole = json.loads((RESULTS / f"accuracy_{target}.json").read_text())
        part = json.loads((RESULTS / f"accuracy_{replay}.json").read_text())
        if (whole["pipeline"], whole["thresholds"], whole["view"]) != (part["pipeline"], part["thresholds"], part["view"]):
            raise SystemExit(f"{replay} ran under other settings than {target}")
        new_run = next(r for r in part["runs"] if r["name"] == TRACE)
        before = next(r for r in whole["runs"] if r["name"] == TRACE)
        whole["runs"] = [new_run if r["name"] == TRACE else r for r in whole["runs"]]
        (RESULTS / f"accuracy_{target}.json").write_text(json.dumps(whole, indent=1))

        tsv = RESULTS / f"alerts_{target}.tsv"
        kept = [l for l in tsv.read_text().splitlines() if not l.startswith(TRACE + "\t")]
        added = (RESULTS / f"alerts_{replay}.tsv").read_text().splitlines()
        tsv.write_text("\n".join(sorted(kept + added, key=lambda l: l.split("\t")[0])) + "\n")
        print(f"{target}: {TRACE} {before['packets']} -> {new_run['packets']} packets, {len(added)} alert lines")


if __name__ == "__main__":
    main()
