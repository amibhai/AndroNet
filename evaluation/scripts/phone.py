#!/usr/bin/env python3
"""Small helpers for driving the evaluation build on an attached phone."""
import os
import subprocess
import time

ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
EVAL_PKG = "com.example.packet_analyzer.eval"
MAIN = f"{EVAL_PKG}/com.example.packet_analyzer.MainActivity"
PCAPDROID = "com.emanuelef.remote_capture"
D = "/data/local/tmp/andronet_eval"


def adb(*args, check=True, capture=True, timeout=None):
    r = subprocess.run(["adb", *args], env=ENV, check=check, timeout=timeout,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    return r.stdout.decode("utf-8", "replace") if capture else ""


def shell(cmd, check=True, timeout=None):
    return adb("shell", cmd, check=check, timeout=timeout)


def vpn_up():
    return " tun" in shell("ip -o -4 addr show", check=False)


def start_andronet(extra=""):
    shell(f"am force-stop {EVAL_PKG}")
    time.sleep(1)
    shell(f"am start -n {MAIN} --es andronet_action start_vpn {extra}")
    for _ in range(20):
        time.sleep(0.5)
        if vpn_up():
            return True
    return False


def stop_andronet():
    # A force-stop tears the tunnel down at once. Sending a stop intent first can relaunch a dead
    # process and bring the tunnel back up behind the caller's back.
    shell(f"am force-stop {EVAL_PKG}", check=False)
    for _ in range(20):
        time.sleep(0.5)
        if not vpn_up():
            return
    raise RuntimeError("tunnel still up after force-stop")


def home():
    shell("input keyevent KEYCODE_HOME", check=False)


def pid_of(pkg):
    return shell(f"pidof {pkg}", check=False).strip().split(" ")[0]


def proc_jiffies(pid):
    """utime+stime of a process, in clock ticks (100 per second on Android)."""
    fields = shell(f"cat /proc/{pid}/stat", check=False).rsplit(")", 1)[-1].split()
    return int(fields[11]) + int(fields[12])


def rss_kib(pid):
    for line in shell(f"grep VmRSS /proc/{pid}/status", check=False).splitlines():
        return int(line.split()[1])
    return 0


def push_harness(build="current"):
    from pathlib import Path
    shell(f"mkdir -p {D}")
    adb("push", str(Path(__file__).resolve().parents[1] / "build" / build / "harness.dex"), f"{D}/{build}.dex")


def harness(args, build="current", timeout=None):
    return shell(f"CLASSPATH={D}/{build}.dex app_process / com.andronet.eval.ReplayMainKt {args}", timeout=timeout)
