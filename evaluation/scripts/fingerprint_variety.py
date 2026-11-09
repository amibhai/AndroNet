#!/usr/bin/env python3
"""How much JA4 varies within one TLS library, which is why the per-app profile keys on the cipher list.

  python fingerprint_variety.py <capture> [<capture> ...]

Writes only counts to results/fingerprint_variety.json, so private captures can be checked too.
"""
import collections
import json
import os
import pathlib
import subprocess
import sys

EVAL = pathlib.Path(__file__).resolve().parents[1]
BUILD = EVAL / "build" / "current"


def stdlib_jar():
    cache = pathlib.Path.home() / ".gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.2.21"
    return str(next(cache.rglob("kotlin-stdlib-2.2.21.jar")))


def main():
    classpath = os.pathsep.join([str(BUILD / "harness.jar"), str(BUILD / "host_classes"), stdlib_jar()])
    results = {}
    for capture in sys.argv[1:]:
        out = subprocess.run(["java", "-cp", classpath, "com.andronet.eval.ReplayMainKt", "fingerprints", "--trace", capture],
                             capture_output=True, text=True, errors="replace").stdout
        full = collections.Counter(line.split()[2] for line in out.splitlines() if len(line.split()) == 3)
        lists = {ja4.split("_")[1] for ja4 in full}
        results[pathlib.Path(capture).stem] = {"hellos": sum(full.values()), "distinctJa4": len(full), "distinctCipherLists": len(lists)}
    (EVAL / "results" / "fingerprint_variety.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results))


if __name__ == "__main__":
    main()
