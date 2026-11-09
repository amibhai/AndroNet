#!/usr/bin/env python3
"""Checks the JA3 and JA4 values AndroNet computes against Wireshark's, on every whole ClientHello.

  python check_fingerprints.py <capture> [<capture> ...]

Writes only counts to results/fingerprint_check.json, so private captures can be checked too.

Chrome now puts a GREASE value inside its signature algorithms, and Wireshark 4.6.5 keeps it, so
Wireshark's JA4 changes on every connection. GREASE is random by design and fingerprints ignore it, so
the expected JA4 is recomputed from Wireshark's raw string with GREASE removed. Both counts are kept.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

EVAL = pathlib.Path(__file__).resolve().parents[1]
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BUILD = EVAL / "build" / "current"


def stdlib_jar():
    cache = pathlib.Path.home() / ".gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.2.21"
    return str(next(cache.rglob("kotlin-stdlib-2.2.21.jar")))


def is_grease(value):
    v = int(value, 16)
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def ja4_without_grease(raw):
    """Wireshark's raw form is prefix_ciphers_extensions_sigalgs, unhashed."""
    parts = raw.split("_")
    if len(parts) < 3:
        return ""
    prefix, ciphers, extensions = parts[0], parts[1], parts[2]
    signatures = parts[3] if len(parts) > 3 else ""
    kept = [s for s in signatures.split(",") if s and not is_grease(s)]
    tail = extensions + ("_" + ",".join(kept) if kept else "")
    sha = lambda text: hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"
    return f"{prefix}_{sha(ciphers)}_{sha(tail)}"


def main():
    totals = {"captures": 0, "wiresharkHellos": 0, "compared": 0, "ja3Match": 0, "ja4MatchAsPrinted": 0, "ja4Match": 0, "notParsed": 0}
    mismatches = []
    classpath = os.pathsep.join([str(BUILD / "harness.jar"), str(BUILD / "host_classes"), stdlib_jar()])
    absent = [c for c in sys.argv[1:] if not os.path.isfile(c)]
    if absent:
        raise SystemExit(f"no such capture: {absent}")
    for capture in sys.argv[1:]:
        totals["captures"] += 1
        ours = {}
        out = subprocess.run(["java", "-cp", classpath, "com.andronet.eval.ReplayMainKt", "fingerprints", "--trace", capture],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            frame, ja3, ja4 = line.split()
            ours[frame] = (ja3, ja4)
        theirs = subprocess.run([TSHARK, "-r", capture, "-Y", "tls.handshake.type == 1 && !quic", "-T", "fields", "-e", "frame.number",
                                 "-e", "tls.handshake.ja3", "-e", "tls.handshake.ja4", "-e", "tls.handshake.ja4_r"],
                                capture_output=True, text=True, errors="replace").stdout
        for line in theirs.splitlines():
            fields = line.split("\t")
            if len(fields) < 4 or not fields[1]:
                continue
            totals["wiresharkHellos"] += 1
            if fields[0] not in ours:
                # Reassembled by Wireshark from several segments; AndroNet fingerprints whole hellos only
                totals["notParsed"] += 1
                continue
            totals["compared"] += 1
            ja3, ja4 = ours[fields[0]]
            totals["ja3Match"] += ja3 == fields[1]
            totals["ja4MatchAsPrinted"] += ja4 == fields[2]
            expected = ja4_without_grease(fields[3])
            totals["ja4Match"] += ja4 == expected
            if (ja3 != fields[1] or ja4 != expected) and len(mismatches) < 8:
                mismatches.append({"frame": fields[0], "ours": [ja3, ja4], "wireshark": [fields[1], expected]})
    (EVAL / "results" / "fingerprint_check.json").write_text(json.dumps(totals, indent=1))
    print(json.dumps(totals))
    for m in mismatches:
        print(m)


if __name__ == "__main__":
    main()
