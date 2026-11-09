#!/usr/bin/env python3
"""Whether a build's capture outlives Android's daily limit on its foreground-service type.

  python fgs_limit_check.py --build v151 --minutes 5   # then the same with --build v152

Android 15 and later allow a data-sync foreground service six hours of running time a day (the
activity_manager setting data_sync_fgs_timeout_duration), and crash an app that keeps one running past
that. Version 1.5.1 declared its VPN service with that type, and a day of everyday use on the Pixel
ended in that crash. Six hours per build is slow to wait out, so this shortens the limit for the test,
installs the build, starts capture, sends the app to the background (the limit is not counted while the app
is on screen), waits past the limit and records whether the process crashed and whether the tunnel is still
up. The setting is restored afterwards, even if the test fails.
Writes results/fgs_limit_<build>.json.
"""
import argparse
import hashlib
import json
import pathlib
import time

import phone
import soak

EVAL = pathlib.Path(__file__).resolve().parents[1]
KEY = "data_sync_fgs_timeout_duration"


def crash_count():
    out = phone.shell(f"dumpsys dropbox --print data_app_crash 2>/dev/null | grep -c 'Process: {phone.EVAL_PKG}$'", check=False).strip()
    return int(out) if out.isdigit() else None


def limit_in_force():
    for line in phone.shell("dumpsys activity settings", check=False).splitlines():
        if line.strip().startswith(KEY + "="):
            return int(line.split("=", 1)[1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True, help="v151 or v152")
    ap.add_argument("--minutes", type=float, default=5, help="the shortened limit")
    ap.add_argument("--margin", type=float, default=3, help="minutes to wait past the limit")
    args = ap.parse_args()
    apk = EVAL / "build" / f"andronet-eval-arm64-{args.build}.apk"
    pkg = phone.EVAL_PKG

    # 1.5.2 to 1.5.1 is a downgrade, which an update would refuse
    phone.adb("uninstall", pkg, check=False)
    phone.adb("install", str(apk))
    phone.shell(f"appops set {pkg} ACTIVATE_VPN allow; appops set {pkg} MANAGE_EXTERNAL_STORAGE allow; "
                f"pm grant {pkg} android.permission.POST_NOTIFICATIONS", check=False)
    names = [line.split("=", 1)[1].strip() for line in phone.shell(f"dumpsys package {pkg}", check=False).splitlines() if "versionName=" in line]
    version = names[0] if names else None
    before = crash_count()
    limit_ms = int(args.minutes * 60_000)
    phone.shell(f"device_config put activity_manager {KEY} {limit_ms}")
    # The limit counts the phone's awake time
    phone.shell("svc power stayon true; input keyevent KEYCODE_WAKEUP", check=False)
    try:
        for _ in range(20):
            if limit_in_force() == limit_ms:
                break
            time.sleep(0.5)
        else:
            raise SystemExit(f"Android did not take the shortened limit; {KEY} is {limit_in_force()}")
        if not phone.start_andronet():
            raise SystemExit("VPN did not come up")
        # Android does not count the limit while the app is on screen, so leave it in the background, as in use
        phone.home()
        pid = phone.pid_of(pkg)
        started = time.time()
        time.sleep((args.minutes + args.margin) * 60)
        waited = (time.time() - started) / 60
        now_pid = phone.pid_of(pkg)
        new_crashes = crash_count() - before
        result = {
            "build": args.build, "versionName": version, "apkSha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
            "limitMinutes": args.minutes, "waitedMinutes": round(waited, 1),
            "sameProcess": bool(pid) and now_pid == pid, "tunnelUp": phone.vpn_up(), "newCrashReports": new_crashes,
            "exception": soak.crash_details()[-1]["exception"] if new_crashes else None,
        }
    finally:
        phone.shell(f"device_config delete activity_manager {KEY}", check=False)
        phone.shell("svc power stayon false", check=False)
        phone.shell(f"am force-stop {pkg}", check=False)
    restored = limit_in_force()
    result["limitAfterRestoreMs"] = restored
    if restored != 21_600_000:
        print(f"warning: {KEY} reads {restored} after restoring, not the stock six hours")
    (EVAL / "results" / f"fgs_limit_{args.build}.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
