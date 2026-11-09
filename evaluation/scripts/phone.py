#!/usr/bin/env python3
"""Small helpers for driving the evaluation build on an attached phone."""
import atexit
import os
import re
import subprocess
import time

ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
EVAL_PKG = "com.example.packet_analyzer.eval"
MAIN = f"{EVAL_PKG}/com.example.packet_analyzer.MainActivity"
PCAPDROID = "com.emanuelef.remote_capture"
D = "/data/local/tmp/andronet_eval"
# adb's words for a phone that is not there, which means the command never reached it
PHONE_GONE = re.compile(r"device .*not found|no devices/emulators found|device offline")


def adb(*args, check=True, capture=True, timeout=None):
    for attempt in range(3):
        r = subprocess.run(["adb", *args], env=ENV, timeout=timeout,
                           stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.STDOUT if capture else None)
        out = r.stdout.decode("utf-8", "replace") if capture else ""
        if r.returncode and capture and PHONE_GONE.search(out) and attempt < 2:
            # A dropped cable costs a wait and no more, and repeating is safe since nothing ran
            subprocess.run(["adb", "wait-for-device"], env=ENV, timeout=900)
            continue
        if r.returncode and check:
            raise subprocess.CalledProcessError(r.returncode, ["adb", *args], output=r.stdout)
        return out
    return out


def shell(cmd, check=True, timeout=None):
    return adb("shell", cmd, check=check, timeout=timeout)


def vpn_up():
    return " tun" in shell("ip -o -4 addr show", check=False)


def quiet():
    """Starts a measurement from a phone with memory to spare. Android's low-memory killer otherwise
    reaches the test processes too. Chrome's tabs come back when it is next opened."""
    shell("am force-stop com.android.chrome; am kill-all", check=False)
    time.sleep(3)


def _stop_capture():
    # Bounded, and past the retries in adb(): if the phone has gone, its own watchdog ends the capture
    try:
        subprocess.run(["adb", "shell", f"am force-stop {EVAL_PKG}; am force-stop {PCAPDROID}"], env=ENV, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        pass


_guarded = False


def guard_capture():
    """Capture carries all of the phone's traffic, so it must not outlive its test. This stops it when
    the script ends, and from the phone's side once the phone has been unplugged for a minute, which also
    covers a laptop that has gone away. Some vendors report a laptop's port as AC power, so either counts. Call it just before starting a capture."""
    global _guarded
    if not _guarded:
        atexit.register(_stop_capture)
        _guarded = True
    # An emulator never reports USB power, and nobody carries one off
    if os.environ.get("ANDROID_SERIAL", "").startswith("emulator"):
        return
    script = (f'away=0; while sleep 30 && {{ pidof {EVAL_PKG} >/dev/null || pidof {PCAPDROID} >/dev/null; }}; do '
              'if dumpsys battery | grep -q -E "(USB|AC) powered: true"; then away=0; else away=$((away + 1)); fi; '
              f'if [ $away -ge 2 ]; then am force-stop {EVAL_PKG}; am force-stop {PCAPDROID}; break; fi; done')
    shell(f"mkdir -p {D}; kill $(cat {D}/capture_watchdog.pid 2>/dev/null) 2>/dev/null; echo '{script}' > {D}/capture_watchdog.sh; "
          f"nohup sh {D}/capture_watchdog.sh > /dev/null 2>&1 & echo $! > {D}/capture_watchdog.pid", check=False)


def start_andronet(extra="", guard=True):
    shell(f"am force-stop {EVAL_PKG}")
    time.sleep(1)
    if guard:
        guard_capture()
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
    if len(fields) < 13:
        raise RuntimeError(f"process {pid} has ended")
    return int(fields[11]) + int(fields[12])


def rss_kib(pid):
    for line in shell(f"grep VmRSS /proc/{pid}/status", check=False).splitlines():
        return int(line.split()[1])
    return 0


class LogStream:
    """Follows the phone's log into a file. Streamed and not read back at the end, since per-connection
    log lines rotate the buffer within minutes and would lose the alerts of the first few. A dropped
    cable ends the stream, so check() restarts it from the last time it was known to be running, and
    close() reads once more for anything after that. Read the file with lines(), which removes repeats."""

    def __init__(self, path, *tags):
        self.path = path
        self.tags = tags
        self.file = open(path, "wb")
        self.since = None
        self.process = self._follow()
        self.restarts = 0

    def _args(self):
        return ["logcat", "-v", "epoch", *(["-T", f"{self.since}.000"] if self.since else []), "-s", *self.tags]

    def _follow(self):
        return subprocess.Popen(["adb", *self._args()], env=ENV, stdout=self.file, stderr=subprocess.DEVNULL)

    def check(self):
        now = shell("date +%s").strip()
        if self.process.poll() is not None:
            self.restarts += 1
            self.process = self._follow()
        self.since = now

    def close(self):
        self.process.terminate()
        self.process.wait(5)
        if self.since:
            self.file.write(adb("logcat", "-d", "-v", "epoch", "-T", f"{self.since}.000", "-s", *self.tags).encode())
        self.file.close()

    def lines(self):
        # Timestamp, thread and text all match only on a repeat written by a restart
        text = self.path.read_text(encoding="utf-8", errors="replace")
        return list(dict.fromkeys(line.strip() for line in text.splitlines()))


def push_harness(build="current"):
    from pathlib import Path
    shell(f"mkdir -p {D}")
    adb("push", str(Path(__file__).resolve().parents[1] / "build" / build / "harness.dex"), f"{D}/{build}.dex")


def harness(args, build="current", timeout=None):
    return shell(f"CLASSPATH={D}/{build}.dex app_process / com.andronet.eval.ReplayMainKt {args}", timeout=timeout)
