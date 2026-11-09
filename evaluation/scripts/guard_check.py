#!/usr/bin/env python3
"""Checks that capture stops itself when the phone leaves the laptop. Android is told it has been unplugged,
for as long as this takes, and the capture must end within two minutes."""
import time

import phone


def main():
    phone.stop_andronet()
    if not phone.start_andronet():
        raise SystemExit("VPN did not come up")
    time.sleep(5)
    if not phone.vpn_up():
        raise SystemExit("capture did not stay up")
    start = time.time()
    try:
        phone.shell("dumpsys battery unplug")
        while phone.vpn_up():
            if time.time() - start > 120:
                raise SystemExit("capture is still running two minutes after the phone was unplugged")
            time.sleep(5)
    finally:
        phone.shell("dumpsys battery reset", check=False)
    print(f"capture ended {time.time() - start:.0f} s after the phone was unplugged")


if __name__ == "__main__":
    main()
