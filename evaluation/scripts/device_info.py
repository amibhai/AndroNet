#!/usr/bin/env python3
"""Records what the attached phone is, for the paper's setup paragraph.

  python device_info.py samsung   # writes results/device_samsung.json
"""
import json
import pathlib
import re
import sys

import phone

EVAL = pathlib.Path(__file__).resolve().parents[1]


def prop(name):
    return phone.shell(f"getprop {name}", check=False).strip()


def market_name():
    # Vendors keep the name a phone is sold under in different properties; ColorOS uses its own
    for name in ("ro.product.vendor.marketname", "ro.product.marketname", "ro.vendor.oplus.market.name", "ro.oppo.market.name"):
        value = prop(name)
        if value:
            return value
    return ""


def main():
    memory = re.search(r"MemTotal:\s+(\d+)", phone.shell("cat /proc/meminfo", check=False))
    info = {
        "manufacturer": prop("ro.product.manufacturer"), "model": prop("ro.product.model"), "marketName": market_name(),
        "soc": prop("ro.soc.model"), "android": prop("ro.build.version.release"), "buildType": prop("ro.build.type"),
        "memTotalGiB": round(int(memory.group(1)) / 1024 / 1024, 1) if memory else None,
    }
    (EVAL / "results" / f"device_{sys.argv[1]}.json").write_text(json.dumps(info, indent=1))
    print(info)


if __name__ == "__main__":
    main()
