#!/usr/bin/env python3
"""Checks, from the capture files, the reason the paper gives for each held-out miss and false alarm.

The scorer says which captures were missed. It cannot say why, so each explanation in the paper
rests on the measurements written here to results/miss_analysis.json. Nothing here feeds back into
the detectors or the limits: the code stayed frozen.
"""
import collections
import json
import math
import pathlib
import re
import subprocess

EVAL = pathlib.Path(__file__).resolve().parents[1]
TRACES = EVAL / "traces" / "test"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
# The pattern of RULE-003, so that the count below is of requests that rule can match
DOWNLOAD_RULE = re.compile(r"\.(exe|scr|bat|cmd|vbs|ps1|dll|jar|apk)(\?.*)?$", re.I)


def fields(trace, display_filter, *names):
    cmd = [TSHARK, "-r", str(TRACES / trace), "-T", "fields", "-E", "separator=|"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for n in names:
        cmd += ["-e", n]
    out = subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout
    return [line.split("|") for line in out.splitlines()]


def per_window(times, seconds):
    """Largest number of events inside any sliding window of the given length."""
    best, start = 0, 0
    for end in range(len(times)):
        while times[end] - times[start] > seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def entropy(data):
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values()) if n else 0.0


def median(values):
    return sorted(values)[len(values) // 2] if values else None


def icmp_flood():
    rows = fields("atk_icmp_flood_large.pcap", "icmp", "frame.time_epoch", "ip.src", "ip.dst", "icmp.type", "data.len")
    by_source = collections.defaultdict(list)
    for r in rows:
        by_source[r[1]].append(float(r[0]))
    times = sorted(float(r[0]) for r in rows)
    sizes = [int(r[4]) for r in rows if r[4].isdigit()]
    return {
        "packets": len(rows),
        "distinctSources": len(by_source),
        "distinctTargets": len({r[2] for r in rows}),
        "packetsPerSourceMax": max(len(v) for v in by_source.values()),
        "maxPerSecondOneSource": max(per_window(sorted(v), 1.0) for v in by_source.values()),
        "maxPerSecondAllSources": per_window(times, 1.0),
        "payloadOver64": sum(1 for s in sizes if s > 64),
        "payloadMedian": median(sizes),
        "durationSeconds": round(times[-1] - times[0], 2) if len(times) > 1 else 0,
    }


def arp_poison():
    rows = fields("atk_arp_poison.pcapng", "arp", "frame.number", "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4")
    bindings = collections.defaultdict(list)
    macs_claiming = collections.defaultdict(set)
    for r in rows:
        ip, mac = r[2], r[3]
        if not bindings[ip] or bindings[ip][-1] != mac:
            bindings[ip].append(mac)
        macs_claiming[mac].add(ip)
    return {
        "arpPackets": len(rows),
        "firstFrames": [{"frame": r[0], "op": r[1], "ip": r[2], "mac": r[3]} for r in rows[:6]],
        "ipsWhoseMacChanged": {ip: m for ip, m in bindings.items() if len(m) > 1},
        "macsClaimingSeveralIps": {m: sorted(i) for m, i in macs_claiming.items() if len(i) > 1},
    }


def dns_remote_shell():
    trace = "atk_dnstunnel_remoteshell.pcap"
    queries = fields(trace, "dns.flags.response == 0", "dns.qry.name")
    shell = [bytes.fromhex(r[0].replace(":", "")) for r in fields(trace, "tcp.port == 53 && tcp.len > 0", "tcp.payload")]
    return {
        "wellFormedDnsQueries": len(queries),
        "nameLengthMax": max(len(r[0]) for r in queries),
        "tcpPort53Segments": len(shell),
        "tcpPort53Bytes": sum(len(s) for s in shell),
        "startsWith": shell[0][:39].decode("ascii", "replace") if shell else "",
        "carriesCmdPrompt": any(b"Microsoft Windows" in s for s in shell),
    }


def dns_txt_c2():
    trace = "atk_dnstunnel_txt_c2.pcap"
    rows = fields(trace, "dns.flags.response == 0", "frame.time_epoch", "dns.qry.name", "udp.length", "dns.qry.type")
    lengths = [len(r[1]) for r in rows]
    txt_times = sorted(float(r[0]) for r in rows if r[3] == "16")
    gaps = [b - a for a, b in zip(txt_times, txt_times[1:])]
    responses = fields(trace, "dns.flags.response == 1 && dns.qry.type == 16", "udp.length", "dns.txt")
    return {
        "queries": len(rows),
        "queryTypes": dict(collections.Counter(r[3] for r in rows)),
        "nameLengthMax": max(lengths),
        "over50Characters": sum(1 for x in lengths if x > 50),
        "queryUdpLengthMax": max(int(r[2]) for r in rows if r[2].isdigit()),
        "txtQueries": len(txt_times),
        "txtMedianGapSeconds": round(median(gaps), 3),
        "txtMaxQueriesPerSecond": per_window(txt_times, 1.0),
        "txtResponses": len(responses),
        "txtResponseUdpLengthMax": max(int(r[0]) for r in responses if r[0].isdigit()),
        "firstResponseIsPowerShell": "nslookup" in responses[0][1] if responses else False,
    }


def nmap_version():
    rows = fields("atk_nmap_version_zeek.pcap", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.src", "tcp.dstport")
    return {
        "synPackets": len(rows),
        "sources": len({r[0] for r in rows}),
        "ports": sorted({int(r[1]) for r in rows if r[1].isdigit()}),
        "layer1FloorPorts": 8,
    }


def ssh_guessing():
    rows = fields("atk_ssh_guessing_zeek.pcap", "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 22", "frame.time_epoch", "ip.src")
    return {
        "synToPort22": len(rows),
        "sources": len({r[1] for r in rows}),
        "maxSynPerMinute": per_window(sorted(float(r[0]) for r in rows), 60.0),
        "ruleFiresAbovePerMinute": 10,
    }


def meterpreter():
    trace = "atk_meterpreter_rdp_tunnel.pcapng"
    segments = [bytes.fromhex(r[0].replace(":", "")) for r in fields(trace, "tcp.port == 4444 && tcp.len > 0", "tcp.payload")]
    raw = (TRACES / trace).read_bytes()
    needles = [b"stdapi_", b"core_channel", b"core_loadlib", b"priv_", b"metsrv", b"meterpreter", b"ReflectiveLoader"]
    return {
        "bytesOnPort4444": sum(len(s) for s in segments),
        "segments": len(segments),
        "medianEntropyBitsPerByte": round(median([entropy(s) for s in segments if len(s) >= 256]), 2),
        "entropyWholeStream": round(entropy(b"".join(segments)), 3),
        "methodStringsInFile": {n.decode(): raw.count(n) for n in needles},
    }


def big_flows():
    trace = "benign_bigFlows.pcap"
    scored = json.loads((EVAL / "results" / "scored.json").read_text())
    per = scored["accuracy_current_test_phone"]["benign"]["perTrace"]["benign_bigFlows"]

    gets = fields(trace, 'http.request.method == "GET"', "ip.src", "ip.dst", "http.request.uri")
    hits = [r for r in gets if DOWNLOAD_RULE.search(r[2].split(",")[0])]
    download = {
        "requests": len(hits),
        "clients": len({r[0] for r in hits}),
        "servers": len({r[1] for r in hits}),
        "paths": dict(collections.Counter(re.sub(r"\?.*", "", r[2]) for r in hits).most_common(4)),
    }

    syn = fields(trace, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "frame.time_epoch", "ip.dst", "ip.src")
    per_sec = collections.Counter()
    clients = collections.defaultdict(set)
    for r in syn:
        key = (int(float(r[0])), r[1])
        per_sec[key] += 1
        clients[key].add(r[2])
    busy = {k: v for k, v in per_sec.items() if v > 30}
    peak_key, peak = per_sec.most_common(1)[0]
    return {
        "alerts": per["alerts"],
        "alertsTotal": sum(per["alerts"].values()),
        "packets": per["packets"],
        "downloadRule": download,
        "synBurst": {
            "secondsOver30SynPerTarget": len(busy),
            "targetsOver30": len({k[1] for k in busy}),
            "peakSynPerSecond": peak,
            "clientsAtPeak": len(clients[peak_key]),
            "medianClientsWhenBusy": median([len(clients[k]) for k in busy]),
        },
    }


def main():
    out = {
        "icmpFlood": icmp_flood(),
        "arpPoison": arp_poison(),
        "dnsRemoteShell": dns_remote_shell(),
        "dnsTxtC2": dns_txt_c2(),
        "nmapVersion": nmap_version(),
        "sshGuessing": ssh_guessing(),
        "meterpreter": meterpreter(),
        "bigFlows": big_flows(),
    }
    (EVAL / "results" / "miss_analysis.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
