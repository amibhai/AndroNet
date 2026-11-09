#!/usr/bin/env python3
"""Quick throughput comparison across capture configurations, for finding the bottleneck."""
import re
import sys
import threading
import time

import phone

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.8"
MB = sys.argv[2] if len(sys.argv) > 2 else "40"


def transfer(direction):
    out = phone.shell(f"CLASSPATH={phone.D}/current.dex app_process / com.andronet.eval.ReplayMainKt transfer "
                      f"--host {HOST} --direction {direction} --mb {MB} --repeat 2; echo rc=$?", check=False, timeout=400)
    rates = [float(x) for x in re.findall(r"([\d.]+) Mbit/s", out)]
    if "rc=0" not in out:
        print("   transfer problem:", out.strip()[-160:], flush=True)
    return rates


def main():
    phone.push_harness()
    phone.stop_andronet()
    print("no vpn          down", transfer("down"), "up", transfer("up"), flush=True)
    for label, extra in (("forward only", "--es analysis off --es ui off"),
                         ("+analysis", "--es ui off"),
                         ("+analysis+ui", "")):
        if not phone.start_andronet(extra):
            print(label, "VPN did not come up")
            continue
        phone.home()
        time.sleep(2)
        pid = phone.pid_of(phone.EVAL_PKG)
        j0 = phone.proc_jiffies(pid)
        t0 = time.time()
        peak = [0]
        done = threading.Event()

        def watch():
            while not done.wait(2):
                try:
                    peak[0] = max(peak[0], phone.rss_kib(pid))
                except Exception:
                    pass

        threading.Thread(target=watch, daemon=True).start()
        down = transfer("down")
        up = transfer("up")
        done.set()
        cpu = (phone.proc_jiffies(pid) - j0) / 100.0 / (time.time() - t0) * 100
        print(f"{label:15s} down {down} up {up} cpu={cpu:.0f}% peak_rss={peak[0] // 1024} MiB alive={phone.pid_of(phone.EVAL_PKG) == pid}", flush=True)
        phone.stop_andronet()


if __name__ == "__main__":
    main()
