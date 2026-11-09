#!/usr/bin/env python3
"""Checks each alert on the fresh attack captures against the flow that raised it.

Capture recall counts a capture as detected when any expected alert fires anywhere in it. These
captures were recorded on working phones and networks, so an alert can land in an attack capture
without being about the attack. This reads the packet behind each alert and counts it only if that
packet belongs to the attack:

  RAT     the packet is to or from the controller
  flood   the packet is to or from the flood's target, the busiest address in the capture

Written after the frozen run, to check its result, so for recall it can only lower the score. The
controllers below come from reading the captures: the peer on the port the RAT's session uses. HawkShaw
shows no such peer, only web and messaging services, so nothing in its capture counts as on the attack.

  python flow_check.py <alerts.tsv> <accuracy tag>
"""
import bisect
import collections
import csv
import json
import pathlib
import subprocess
import sys

from test_manifest_v2 import ATTACKS

EVAL = pathlib.Path(__file__).resolve().parents[1]
FRESH = pathlib.Path(r"D:\andronet_eval\fresh")
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# Controller of each RAT capture as (address, port), where None matches anything
CONTROLLERS = {
    "atk_fresh_rat_androidtester": ("147.32.83.234", 1337),
    "atk_fresh_rat_droidjack": ("147.32.83.253", 1337),
    "atk_fresh_rat_hawkshaw": ("no controller seen", None),
    "atk_fresh_rat_spymax": ("147.32.83.181", 8000),
    "atk_fresh_rat_androrat": ("147.32.83.234", 1337),
    "atk_fresh_rat_saefko": (None, 6667),
    "atk_fresh_rat_ahmyth": ("147.32.83.230", 8000),
    "atk_fresh_rat_cli_androrat": ("147.32.83.157", 1337),
}


def packets(path):
    cmd = [TSHARK, "-r", str(path), "-T", "fields", "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
           "-e", "ipv6.src", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport"]
    frames = {}
    busiest = collections.Counter()
    for line in subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout.splitlines():
        p = line.split("\t")
        if len(p) < 10:
            continue
        src, dst = p[2] or p[4], p[3] or p[5]
        # Fragments and ICMP quote more than one header: the outermost is first
        src, dst = src.split(",")[0], dst.split(",")[0]
        sport, dport = (p[6] or p[8]).split(",")[0], (p[7] or p[9]).split(",")[0]
        frames[int(p[0])] = (float(p[1]) * 1000, src, dst, sport, dport)
        busiest[dst] += 1
    return frames, busiest


def find(frames, times, index, millis):
    """The packet behind an alert: by its position where the replay read every frame, else by its time,
    taking the nearest in position among the frames of that millisecond."""
    for k in (index, index + 1, index - 1):
        f = frames.get(k)
        if f and abs(f[0] - millis) < 2:
            return f
    left = bisect.bisect_left(times, (millis - 1, 0))
    right = bisect.bisect_right(times, (millis + 1, float("inf")))
    if left == right:
        return None
    number = min((times[i][1] for i in range(left, right)), key=lambda n: abs(n - index))
    return frames[number]


def belongs(name, frame, target):
    _, src, dst, sport, dport = frame
    if name in CONTROLLERS:
        address, port = CONTROLLERS[name]
        ok_address = address is None or address in (src, dst)
        ok_port = port is None or str(port) in (sport, dport)
        return ok_address and ok_port
    return target in (src, dst)


def main():
    alerts_path, tag = sys.argv[1], sys.argv[2]
    expected = {k: set(v["expect"]) for k, v in ATTACKS.items() if v["expect"]}
    alerts = collections.defaultdict(list)
    with open(alerts_path, encoding="utf-8") as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) >= 5 and row[0] in expected:
                alerts[row[0]].append((int(row[2]), int(row[3]), row[4]))

    results = {}
    for name in expected:
        kept, thrown = collections.Counter(), collections.Counter()
        where = {}
        unmatched = 0
        capture_hit = flow_hit = False
        if alerts[name]:
            frames, busiest = packets(next(FRESH.glob(f"{name}.*")))
            target = busiest.most_common(1)[0][0] if busiest else ""
            times = sorted((f[0], n) for n, f in frames.items())
            for index, millis, finding in alerts[name]:
                frame = find(frames, times, index, millis)
                if frame is None:
                    unmatched += 1
                    continue
                on_attack = belongs(name, frame, target)
                (kept if on_attack else thrown)[finding] += 1
                where.setdefault(finding, f"{frame[1]}>{frame[2]}:{frame[4]}")
                if finding in expected[name]:
                    capture_hit = True
                    flow_hit = flow_hit or on_attack
        results[name] = {"class": ATTACKS[name]["class"], "capture": capture_hit, "flow": flow_hit, "onAttack": dict(kept),
                         "elsewhere": dict(thrown), "unmatched": unmatched, "example": where}
        mark = "FLOW" if flow_hit else ("capt" if capture_hit else "    ")
        print(f"{mark} {name:42s} on attack {dict(kept)} elsewhere {dict(thrown)} unmatched {unmatched}")

    classes = collections.defaultdict(lambda: [0, 0, 0])
    for r in results.values():
        c = classes[r["class"]]
        c[0] += r["flow"]
        c[1] += r["capture"]
        c[2] += 1
    on = sum(sum(r["onAttack"].values()) for r in results.values())
    off = sum(sum(r["elsewhere"].values()) for r in results.values())
    print("by class (flow-checked, capture-level, total):", dict(classes))
    print("recall", sum(r["flow"] for r in results.values()), "of", len(results), "capture level", sum(r["capture"] for r in results.values()))
    print(f"alerts on attack flows {on}, elsewhere {off}")
    out = EVAL / "results" / f"flow_check_{tag}.json"
    out.write_text(json.dumps({"captures": results, "alertsOnAttack": on, "alertsElsewhere": off,
                               "byClass": {k: dict(zip(("flow", "capture", "total"), v)) for k, v in classes.items()}}, indent=1))


if __name__ == "__main__":
    main()
