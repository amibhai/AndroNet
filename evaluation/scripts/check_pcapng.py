#!/usr/bin/env python3
"""Walks a pcapng file block by block and reports whether it ends on a block boundary."""
import struct
import sys

NAMES = {0x0A0D0D0A: "SHB", 1: "IDB", 6: "EPB", 5: "ISB"}


def check(path):
    data = open(path, "rb").read()
    off, counts = 0, {}
    last_ok = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        if blen < 12 or blen % 4 or off + blen > len(data):
            break
        trail = struct.unpack_from("<I", data, off + blen - 4)[0]
        if trail != blen:
            print(f"  length mismatch at {off}: leading {blen}, trailing {trail}")
            break
        name = NAMES.get(btype, hex(btype))
        counts[name] = counts.get(name, 0) + 1
        off += blen
        last_ok = off
    print(f"{path.split(chr(92))[-1]}: size={len(data)} last_good_block_end={last_ok} leftover={len(data) - last_ok} blocks={counts}")
    if last_ok < len(data):
        print("  tail bytes:", data[last_ok:last_ok + 32].hex(), "header:", struct.unpack_from("<II", data, last_ok) if last_ok + 8 <= len(data) else "")


for p in sys.argv[1:]:
    check(p)
