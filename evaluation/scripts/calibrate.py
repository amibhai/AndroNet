#!/usr/bin/env python3
"""Prints the distribution of the rate features that detection thresholds act on, for a capture.

Used on development traffic only. Thresholds are set above what benign traffic reaches, with a
margin, and then frozen before the held-out set is touched.
"""
import collections
import json
import pathlib
import struct
import sys

import dpkt


def packets(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        link = reader.datalink()
        for ts, buf in reader:
            yield float(ts), link, buf


def ip_of(link, buf):
    if link == 1:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if link in (101, 12, 14):
        v = buf[0] >> 4
        return dpkt.ip.IP(buf) if v == 4 else dpkt.ip6.IP6(buf) if v == 6 else None
    if link in (0, 108):
        v = buf[4] >> 4
        return dpkt.ip.IP(buf[4:]) if v == 4 else dpkt.ip6.IP6(buf[4:]) if v == 6 else None
    return None


def pct(values, q):
    if not values:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * q))]


def main():
    path = sys.argv[1]
    syn_per_sec = collections.Counter()
    syn_dst_per_sec = collections.Counter()
    dests_per_10s = collections.defaultdict(set)
    ports_per_10s = collections.defaultdict(set)
    big_out_per_10s = collections.Counter()
    longest = collections.Counter()
    total = 0
    t0 = None
    for ts, link, buf in packets(path):
        try:
            ip = ip_of(link, buf)
        except Exception:
            continue
        if ip is None:
            continue
        total += 1
        t0 = t0 if t0 is not None else ts
        sec = int(ts - t0)
        win = sec // 10
        src = bytes(ip.src)
        dst = bytes(ip.dst)
        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP):
            payload = len(l4.data)
            if l4.flags & dpkt.tcp.TH_SYN and not l4.flags & dpkt.tcp.TH_ACK:
                syn_per_sec[(src, sec)] += 1
                syn_dst_per_sec[(dst, sec)] += 1
            if not l4.flags & dpkt.tcp.TH_ACK:
                dests_per_10s[(src, win)].add(dst)
                ports_per_10s[(src, win)].add(l4.dport)
            outgoing = l4.dport < l4.sport
        elif isinstance(l4, dpkt.udp.UDP):
            payload = len(l4.data)
            outgoing = l4.dport < l4.sport
            if l4.dport == 53:
                try:
                    q = dpkt.dns.DNS(l4.data)
                    if q.qd:
                        longest[len(q.qd[0].name)] += 1
                except Exception:
                    pass
        else:
            continue
        if outgoing and payload > 1024:
            big_out_per_10s[(src, win)] += 1

    summary = {"ipPackets": total, "seconds": sec}
    print(f"{path}: {total} IP packets, {sec} s")
    for name, counter in (("new connections / s per source", syn_per_sec),
                          ("SYN / s per target", syn_dst_per_sec),
                          ("outgoing >1024 B packets / 10 s per source", big_out_per_10s)):
        vals = list(counter.values())
        print(f"{name:46s} p50={pct(vals, .5)} p90={pct(vals, .9)} p99={pct(vals, .99)} max={max(vals) if vals else 0}")
        summary[name] = max(vals) if vals else 0
    for name, sets in (("distinct destinations probed / 10 s per source", dests_per_10s),
                       ("distinct ports probed / 10 s per source", ports_per_10s)):
        vals = [len(v) for v in sets.values()]
        print(f"{name:46s} p50={pct(vals, .5)} p90={pct(vals, .9)} p99={pct(vals, .99)} max={max(vals) if vals else 0}")
        summary[name] = max(vals) if vals else 0
    lens = sorted(longest.elements())
    if lens:
        print(f"{'DNS query name length':46s} p50={pct(lens, .5)} p90={pct(lens, .9)} p99={pct(lens, .99)} max={lens[-1]} over50={sum(1 for x in lens if x > 50)} of {len(lens)}")
    if len(sys.argv) > 2:
        pathlib.Path(sys.argv[2]).write_text(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
