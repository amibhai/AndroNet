#!/usr/bin/env python3
"""Generates benign phone traffic under a live capture and records what the app reported.

  python benign_session.py --list dev --tag dev
  python benign_session.py --list fresh --tag fresh_pixel --apps

Opens public sites in the phone's browser, one every --dwell seconds, with some scrolling. With
--apps it then opens common apps in turn, launching each and touching nothing inside it. The
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
    # Not browsed by anything until the v1.5 freeze
    "fresh": ["https://www.aljazeera.com", "https://timesofindia.indiatimes.com", "https://www.ebay.com", "https://www.nasa.gov",
              "https://www.nationalgeographic.com", "https://www.tripadvisor.in", "https://www.khanacademy.org", "https://www.coursera.org",
              "https://www.nature.com", "https://www.isro.gov.in", "https://www.bookmyshow.com", "https://www.ajio.com",
              "https://www.mozilla.org", "https://www.python.org", "https://www.weather.com", "https://www.flickr.com",
              "https://www.deccanherald.com", "https://www.livemint.com", "https://www.bbc.co.uk/sport", "https://www.etsy.com"],
}
SITES["dev2"] = SITES["dev"] + SITES["test"]
APPS = ["com.google.android.youtube", "com.google.android.apps.maps", "com.android.vending", "com.google.android.gm",
        "com.google.android.apps.photos", "com.google.android.apps.messaging", "com.google.android.calendar",
        "com.google.android.apps.docs", "com.google.android.googlequicksearchbox", "com.sec.android.app.samsungapps"]
ALERT = re.compile(r"ANOMALY: (\S+) - (.*)$")
TAG = re.compile(r"^\[([A-Z0-9-]+)\]")
APP = re.compile(r"\(app: (.*)\)$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default="dev", choices=list(SITES))
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--dwell", type=int, default=25)
    ap.add_argument("--learn", type=int, default=62)
    ap.add_argument("--export", action="store_true", default=True)
    ap.add_argument("--apps", action="store_true")
    ap.add_argument("--no-identity", action="store_true", help="run without app identity, to measure what it adds")
    args = ap.parse_args()

    private = EVAL / "results" / "private"
    private.mkdir(parents=True, exist_ok=True)
    phone.stop_andronet()
    if not phone.start_andronet("--es identity off" if args.no_identity else ""):
        raise SystemExit("VPN did not come up")
    name = f"benign_{args.tag}.pcapng"
    exports_before = set(phone.shell("ls /sdcard/Download/AndroNet/", check=False).split())
    if args.export:
        phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_start --es name {name}")
        time.sleep(1)
    phone.home()

    phone.adb("logcat", "-c")
    log = phone.LogStream(private / f"benign_{args.tag}.logcat", "PacketAnalysisManager:W", "PcapWriter:*", "AndroNet:*")

    pid = phone.pid_of(phone.EVAL_PKG)
    # Browsing starts straight away so the learning period sees real traffic
    start = time.time()
    j0 = phone.proc_jiffies(pid)
    installed = phone.shell("pm list packages", check=False)
    browser = "-p com.android.chrome" if "package:com.android.chrome" in installed else ""
    for url in SITES[args.list]:
        log.check()
        if not phone.vpn_up():
            raise SystemExit("capture is not running: session abandoned")
        phone.shell(f"am start -a android.intent.action.VIEW -d '{url}' {browser}", check=False)
        for _ in range(max(1, args.dwell // 8)):
            time.sleep(8)
            phone.shell("input swipe 500 1600 500 500 300", check=False)
    if args.apps:
        for app in APPS:
            if f"package:{app}" in installed:
                log.check()
                phone.shell(f"monkey -p {app} -c android.intent.category.LAUNCHER 1", check=False)
                time.sleep(args.dwell)
        phone.home()
    elapsed = time.time() - start
    cpu = (phone.proc_jiffies(pid) - j0) / 100.0 / elapsed * 100
    rss = phone.rss_kib(pid) // 1024

    phone.home()
    time.sleep(2)
    if args.export:
        phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_stop")
        time.sleep(3)
        phone.home()
    log.close()
    phone.stop_andronet()

    counts = {}
    by_app = {}
    for raw in log.lines():
        m = ALERT.search(raw)
        if m:
            t = TAG.match(m.group(2))
            aid = t.group(1) if t else "L1:" + m.group(1)
            counts[aid] = counts.get(aid, 0) + 1
            owner = APP.search(m.group(2))
            by_app[owner.group(1) if owner else "(unattributed)"] = by_app.get(owner.group(1) if owner else "(unattributed)", 0) + 1

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

    result = {"tag": args.tag, "sites": len(SITES[args.list]), "seconds": round(elapsed), "alerts": counts, "alertsByApp": by_app,
              "cpuPercent": round(cpu, 1), "rssMiB": rss, **pcap_info}
    (EVAL / "results" / f"benign_live_{args.tag}.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
