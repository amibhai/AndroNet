#!/usr/bin/env python3
"""Checks the paper's export claim on the phone: the pcapng opens in tshark and flagged packets carry
their annotation. Generates a scan so that some packets score high enough to be annotated."""
import json
import pathlib
import subprocess
import time

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
NAME = "annotation_check.pcapng"


def main():
    phone.push_harness()
    phone.stop_andronet()
    if not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_start --es name {NAME}")
    time.sleep(1)
    phone.home()
    print("learning period: 62 s", flush=True)
    time.sleep(62)
    print(phone.harness("livegen --host 192.168.1.8 --only port_scan_connect,syn_flood --settle 2000 --out "
                        f"{phone.D}/live_annot.txt", timeout=200).strip(), flush=True)
    phone.shell(f"am start -n {phone.MAIN} --es andronet_action export_stop")
    time.sleep(3)
    phone.stop_andronet()

    local = EVAL / "results" / "private" / NAME
    local.parent.mkdir(parents=True, exist_ok=True)
    print(phone.adb("pull", f"/sdcard/Download/AndroNet/{NAME}", str(local), check=False).strip()[-90:])
    phone.shell(f"rm -f /sdcard/Download/AndroNet/{NAME}", check=False)

    info = subprocess.run([r"C:\Program Files\Wireshark\capinfos.exe", "-c", "-t", "-E", "-T", "-m", "-Q", str(local)], capture_output=True, text=True)
    print(info.stdout.strip()[-200:], info.stderr.strip()[-200:])
    verbose = subprocess.run([TSHARK, "-r", str(local), "-V", "-c", "4000"], capture_output=True, text=True, errors="replace").stdout
    annotated = verbose.count("anomaly_score")
    fields = subprocess.run([TSHARK, "-r", str(local), "-T", "fields", "-e", "frame.comment", "-Y", "frame.comment"],
                            capture_output=True, text=True, errors="replace").stdout.strip().splitlines()
    hexdump = local.read_bytes()
    raw_hits = hexdump.count(b"anomaly_score=")
    result = {"annotatedInTsharkVerbose": annotated, "frameCommentPackets": len(fields), "annotationStringsInFile": raw_hits,
              "capinfos": info.stdout.strip().splitlines()[-1].replace(str(local), pathlib.Path(local).name) if info.stdout.strip() else ""}
    print(json.dumps(result, indent=1))
    (EVAL / "results" / "annotation_check.json").write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
