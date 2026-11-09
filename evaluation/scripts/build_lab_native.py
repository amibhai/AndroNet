#!/usr/bin/env python3
"""Cross-compiles the small native test tools with the NDK. Output: build/native/<abi>/."""
import os
import pathlib
import subprocess

EVAL = pathlib.Path(__file__).resolve().parents[1]
NDK = pathlib.Path(os.environ.get("ANDROID_HOME") or pathlib.Path.home() / "AppData/Local/Android/Sdk") / "ndk/28.2.13676358"
CLANG = NDK / "toolchains/llvm/prebuilt/windows-x86_64/bin"
TARGETS = {"x86_64": "x86_64-linux-android33-clang.cmd", "arm64-v8a": "aarch64-linux-android33-clang.cmd"}

for abi, compiler in TARGETS.items():
    out = EVAL / "build" / "native" / abi
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(CLANG / compiler), "-O2", "-fPIE", "-pie", str(EVAL / "lab/pcap_inject.c"), "-o", str(out / "pcap_inject")], check=True)
    print("built", out / "pcap_inject")
