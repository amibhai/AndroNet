#!/usr/bin/env python3
"""Mean and busiest-second rates of the held-out phone session. Writes aggregates only: the capture
itself stays in results/private/."""
import collections
import json
import pathlib
import subprocess

EVAL = pathlib.Path(__file__).resolve().parents[1]
CAPTURE = EVAL / "results" / "private" / "benign_phone_test" / "benign_phone_test_00.pcapng"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def main():
    out = subprocess.run([TSHARK, "-r", str(CAPTURE), "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len"],
                         capture_output=True, text=True).stdout
    bytes_per_sec, packets_per_sec = collections.Counter(), collections.Counter()
    first, last = None, None
    for line in out.splitlines():
        t, size = line.split()
        t = float(t)
        bytes_per_sec[int(t)] += int(size)
        packets_per_sec[int(t)] += 1
        first = t if first is None else first
        last = t
    total_packets = sum(packets_per_sec.values())
    seconds = last - first
    result = {"packets": total_packets, "seconds": round(seconds, 1),
              "meanMbps": round(sum(bytes_per_sec.values()) * 8 / seconds / 1e6, 2),
              "meanPps": round(total_packets / seconds, 1),
              "peakSecondMbps": round(max(bytes_per_sec.values()) * 8 / 1e6, 2),
              "peakSecondPps": max(packets_per_sec.values())}
    (EVAL / "results" / "benign_live_rates.json").write_text(json.dumps(result, indent=1))
    print(result)


if __name__ == "__main__":
    main()
