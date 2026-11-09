#!/usr/bin/env python3
"""Reads the phone's current screen with uiautomator and taps elements by their text."""
import re
import time

import phone


def elements():
    phone.shell("uiautomator dump /sdcard/ui.xml >/dev/null 2>&1", check=False)
    xml = phone.shell("cat /sdcard/ui.xml", check=False)
    found = []
    for m in re.finditer(r'<node [^>]*?text="([^"]*)"[^>]*?content-desc="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        text, desc, x1, y1, x2, y2 = m.groups()
        if text or desc:
            found.append((text or desc, (int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2))
    return found


def show():
    for text, x, y in elements():
        print(f"  {text[:70]!r} @ {x},{y}")


def tap_text(*wanted, timeout=8):
    """Taps the first on-screen element whose text matches one of the given (case-insensitive) patterns."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for text, x, y in elements():
            for w in wanted:
                if re.fullmatch(w, text, re.I):
                    phone.shell(f"input tap {x} {y}", check=False)
                    return text
        time.sleep(0.5)
    return None
