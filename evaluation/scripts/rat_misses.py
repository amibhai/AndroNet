#!/usr/bin/env python3
"""Why the frozen build missed the RATs it missed: what each controller flow opens with, its timing,
and whether DNS explained the addresses that raised the beacon test's false alarms. Reads the fresh
captures only, after the frozen run, and changes nothing in the build. Prints flow statistics, no
payload contents.

  python rat_misses.py
"""
import json
import pathlib
import subprocess

from flow_check import CONTROLLERS, FRESH, TSHARK

EVAL = pathlib.Path(__file__).resolve().parents[1]
# Where a capture's controller is known only as a port on a range, the busiest flow on it is the session
FIND = {"atk_fresh_rat_droidjack": "147.32.83.", "atk_fresh_rat_hawkshaw": "147.32.83.", "atk_fresh_rat_androrat": "147.32.83."}


def tshark(path, display, *fields):
    cmd = [TSHARK, "-r", str(path), "-Y", display, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    return [line.split("\t") for line in subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout.splitlines()]


def opaque_view(data):
    """The same tests as FlowDetectors.isOpaque, for reporting."""
    if not data:
        return {}
    bits = sum(bin(b).count("1") for b in data) / len(data)
    printable = sum(0x20 <= b <= 0x7e for b in data)
    run = longest = 0
    for b in data:
        run = run + 1 if 0x20 <= b <= 0x7e else 0
        longest = max(longest, run)
    return {"bytes": len(data), "bitsPerByte": round(bits, 2), "printableShare": round(printable / len(data), 2),
            "longestPrintableRun": longest, "first6Printable": all(0x20 <= b <= 0x7e for b in data[:6])}


def controller_flows(path, name):
    address, port = CONTROLLERS[name]
    if name in FIND:
        rows = tshark(path, f"tcp && ip.dst >= {FIND[name]}0 && ip.dst <= {FIND[name]}255", "ip.dst", "tcp.dstport")
        counts = {}
        for dst, dport in rows:
            counts[(dst, dport)] = counts.get((dst, dport), 0) + 1
        if not counts:
            return None, None
        (address, port), _ = max(counts.items(), key=lambda kv: kv[1])
    return address, port


def main():
    report = {}
    for name in CONTROLLERS:
        path = next(FRESH.glob(f"{name}.*"))
        address, port = controller_flows(path, name)
        row = {"controllerPort": port}
        display = f"tcp.port == {port}" if address is None else f"ip.addr == {address} && tcp.port == {port}"
        packets = tshark(path, display + " && tcp.len > 0", "tcp.stream", "frame.time_epoch", "tcp.dstport", "tcp.payload")
        streams = {}
        for stream, when, dport, payload in (p for p in packets if len(p) == 4):
            streams.setdefault(stream, []).append((float(when), int(dport), payload))
        row["streams"] = len(streams)
        syns = {s[0] for s in tshark(path, display + " && tcp.flags.syn == 1 && tcp.flags.ack == 0", "tcp.stream")}
        row["streamsWithHandshake"] = len(syns & set(streams))
        firsts = []
        for stream, items in streams.items():
            if stream in syns:
                when, dport, payload = items[0]
                view = opaque_view(bytes.fromhex(payload.replace(":", "")))
                view["fromClient"] = str(dport) == str(port)
                firsts.append(view)
        row["firstPayloads"] = firsts[:4]
        report[name] = row

        # Addresses behind the false alarms: did this capture ever show a DNS answer for them?
        answers = tshark(path, "dns.flags.response == 1 && dns.a", "dns.a")
        known = {a for row_ in answers for a in row_[0].split(",")}
        report[name]["dnsAnswers"] = len(known)
        report[name]["sawTwitterAnswer"] = any(a.startswith("104.244.42.") for a in known)
        print(name, json.dumps(row, indent=None)[:600])
    (EVAL / "results" / "rat_misses.json").write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
