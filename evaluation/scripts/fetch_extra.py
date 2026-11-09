#!/usr/bin/env python3
"""Unpacks the archived held-out captures.

The WannaCry capture is real worm traffic in a password-protected archive, published for analysis.
It is treated as data only: nothing is carved from it or run, it is kept outside the repository,
and it is not redistributed. Security software may flag the file, in which case leave it flagged
and evaluate without it.
"""
import pathlib
import sys
import urllib.request
import zipfile

EVAL = pathlib.Path(__file__).resolve().parents[1]
TEST = EVAL / "traces/test"
LARGE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else TEST
MTA = ("https://www.malware-traffic-analysis.net/2017/05/18/"
       "2017-05-18-WannaCry-ransomware-using-EnternalBlue-exploit.pcap.zip")

with zipfile.ZipFile(TEST / "nmap_captures.zip") as z:
    for info in z.infolist():
        name = info.filename.rsplit("/", 1)[-1]
        if name.startswith("nmap_"):
            out = TEST / ("atk_wsnmap_" + name[len("nmap_"):] + ".pcap")
            out.write_bytes(z.read(info))
            print("extracted", out.name, out.stat().st_size)
    print(z.read("README.txt").decode("latin-1")[:1600])

archive = LARGE / "wannacry.pcap.zip"
if not archive.exists():
    req = urllib.request.Request(MTA, headers={"User-Agent": "Mozilla/5.0 (research; AndroNet evaluation)"})
    with urllib.request.urlopen(req, timeout=200) as r, open(archive, "wb") as f:
        f.write(r.read())
print("archive", archive.stat().st_size)
try:
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            print(info.file_size, info.filename)
            if info.filename.lower().endswith((".pcap", ".pcapng")):
                (LARGE / "atk_wannacry_eternalblue.pcap").write_bytes(z.read(info, pwd=b"infected_20170518"))
                print("extracted atk_wannacry_eternalblue.pcap")
except Exception as e:
    print("could not unpack:", repr(e))
