#!/usr/bin/env python3
"""Generates benign phone traffic under a live capture and records what the app reported.

  python benign_session.py --list dev --tag dev

Opens public sites in the phone's browser, one every --dwell seconds, with some scrolling. The
AndroNet pcapng export of the session goes to results/private/ and stays on this machine.
Only aggregate counts are kept in results/.
"""
import argparse
import json
import pathlib
import re
import subprocess
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]

# Two disjoint lists: the test list is never browsed until the code is frozen.
SITES = {
    "dev": ["https://www.wikipedia.org", "https://www.bbc.com/news", "https://github.com/explore", "https://stackoverflow.com",
            "https://www.reddit.com", "https://www.nytimes.com", "https://www.amazon.in", "https://www.flipkart.com",
            "https://www.youtube.com", "https://www.google.com/maps", "https://www.hindustantimes.com", "https://www.ndtv.com",
            "https://www.imdb.com", "https://www.booking.com", "https://www.espncricinfo.com"],
    "test": ["https://www.theguardian.com", "https://www.cnn.com", "https://www.indiatoday.in", "https://www.thehindu.com",
             "https://www.myntra.com", "https://www.snapdeal.com", "https://www.quora.com", "https://medium.com",
             "https://www.twitch.tv", "https://www.spotify.com", "https://www.w3schools.com", "https://www.geeksforgeeks.org",
             "https://www.irctc.co.in", "https://www.makemytrip.com", "https://www.zomato.com", "https://www.swiggy.com",
             "https://www.pinterest.com", "https://www.linkedin.com", "https://www.microsoft.com", "https://www.apple.com"],
}
ALERT = re.compile(r"ANOMALY: (\S+) - (.*)$")
TAG = re.compile(r"^\[([A-Z0-9-]+)\]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default="dev", choices=list(SITES))
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--dwell", type=int, default=25)
    ap.add_argument("--learn", type=int, default=62)
    ap.add_argument("--export", action="store_true", default=True)
    args = ap.parse_args()

    private = EVAL / "results" / "private"
    private.mkdir(parents=True, exist_ok=True)
    phone.stop_andronet()
    if not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    name = f"benign_{args.tag}.pcapng"
    exports_before = set(phone.shell("ls /sdcard/Download/AndroNet/", check=False).split())
    if args.export:
        phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_start --es name {name}")
        time.sleep(1)
    phone.home()

    log_path = private / f"benign_{args.tag}.logcat"
    log_file = open(log_path, "wb")
    phone.adb("logcat", "-c")
    streamer = subprocess.Popen(["adb", "logcat", "-v", "epoch", "-s", "PacketAnalysisManager:W", "PcapWriter:*", "AndroNet:*"],
                                env=phone.ENV, stdout=log_file, stderr=subprocess.DEVNULL)

    pid = phone.pid_of(phone.EVAL_PKG)
    # Browsing starts straight away so the learning period sees real traffic
    start = time.time()
    j0 = phone.proc_jiffies(pid)
    for url in SITES[args.list]:
        phone.shell(f"am start -a android.intent.action.VIEW -d '{url}' -p com.android.chrome", check=False)
        for _ in range(max(1, args.dwell // 8)):
            time.sleep(8)
            phone.shell("input swipe 500 1600 500 500 300", check=False)
    elapsed = time.time() - start
    cpu = (phone.proc_jiffies(pid) - j0) / 100.0 / elapsed * 100
    rss = phone.rss_kib(pid) // 1024

    phone.home()
    time.sleep(2)
    if args.export:
        phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_stop")
        time.sleep(3)
        phone.home()
    streamer.terminate()
    streamer.wait(5)
    log_file.close()
    phone.stop_andronet()

    counts = {}
    for raw in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = ALERT.search(raw)
        if m:
            t = TAG.match(m.group(2))
            aid = t.group(1) if t else "L1:" + m.group(1)
            counts[aid] = counts.get(aid, 0) + 1

    pcap_info = {}
    if args.export:
        # The writer rotates files by size, and only the first carries the session's name; the
        # rest are named andronet_<time>_<n>. So take everything this session added to the folder.
        after = set(phone.shell("ls /sdcard/Download/AndroNet/", check=False).split())
        listing = sorted(after - exports_before, key=lambda f: (not f.startswith("benign_"), f))
        folder = private / f"benign_phone_{args.tag}"
        folder.mkdir(exist_ok=True)
        total = 0
        for i, remote in enumerate(listing):
            local = folder / f"benign_phone_{args.tag}_{i:02d}.pcapng"
            phone.adb("pull", f"/sdcard/Download/AndroNet/{remote}", str(local), check=False)
            info = subprocess.run([r"C:\Program Files\Wireshark\capinfos.exe", "-c", "-T", "-m", "-Q", str(local)],
                                  capture_output=True, text=True).stdout.strip().splitlines()
            if info:
                total += int(info[-1].rsplit(",", 1)[-1].strip('"'))
            # The capture itself stays private; remove it from the phone's shared storage
            phone.shell(f"rm -f /sdcard/Download/AndroNet/{remote}", check=False)
        pcap_info = {"exportFiles": len(listing), "exportPackets": total}

    result = {"tag": args.tag, "sites": len(SITES[args.list]), "seconds": round(elapsed), "alerts": counts,
              "cpuPercent": round(cpu, 1), "rssMiB": rss, **pcap_info}
    (EVAL / "results" / f"benign_live_{args.tag}.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
