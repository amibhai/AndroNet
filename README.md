<div align="center">

# AndroNet

**Mobile Network Packet Analyzer for Kali NetHunter**

A professional-grade mobile network security analysis platform for penetration testers, network administrators, and cybersecurity professionals.

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![PR Check](https://img.shields.io/badge/PR%20Check-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-NetHunter%20%7C%20Android-blue)
![Language](https://img.shields.io/badge/language-Kotlin%20%7C%20C%20%7C%20Dart-orange)
![Framework](https://img.shields.io/badge/framework-Flutter-02569B)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

[Installation](#installation) • [Features](#features) • [Architecture](#system-architecture) • [Usage](#usage) • [Troubleshooting](#troubleshooting)

</div>

---

## Overview

AndroNet brings Wireshark-class packet analysis natively to Android. Built for integration with **Kali NetHunter**, it delivers real-time network monitoring, deep packet inspection (DPI), and adaptive anomaly detection — running efficiently on mobile hardware, with or without root.

### Problem Statement

Mobile security professionals have long lacked a native, Wireshark-like packet analysis tool for Android that integrates cleanly with Kali NetHunter. AndroNet closes that gap: real-time monitoring, deep packet inspection, and anomaly detection, without breaking the device's internet connectivity or requiring a desktop tether.

### Target Users

- Penetration testers using Kali NetHunter
- Network administrators monitoring mobile networks
- Cybersecurity researchers conducting traffic analysis
- Students learning network security concepts
- Security operations teams performing incident response

### Key Challenges Solved

| Challenge | Solution |
|---|---|
| Packet capture on mobile | Full capture without breaking internet connectivity |
| Deep inspection | Application-layer analysis (HTTP, DNS, TLS, DHCP) |
| Root fragmentation | Dual-mode operation — AF_PACKET helper (rooted) or VPN (unrooted) |
| Real-time visibility | Live traffic statistics and anomaly detection |
| Forensic handoff | Standard PCAP export for Wireshark |

---

## Features

### Complete Network Visibility

- **Dual-mode packet capture**
  - **VPN mode** (unrooted): zero-setup capture via Android VPN API + zdtun
  - **Root mode**: a small helper started through `su` captures on an AF_PACKET socket, which adds inbound scans, ARP and other link-level traffic a VPN can never see
- Both modes feed one record builder and one analysis pipeline
- Internet connectivity maintained throughout
- TCP, UDP, ICMP on both paths; ARP and DHCP on the root path

### Deep Packet Inspection (DPI)

<table>
<tr><td width="25%"><b>HTTP/HTTPS</b></td><td>Request methods, URI/path extraction, response codes, headers (Host, User-Agent, Cookie, Content-Type), TLS handshake detection</td></tr>
<tr><td><b>DNS</b></td><td>Query/response typing, domain extraction, record types (A, AAAA, CNAME, MX, TXT, PTR, SRV), response codes, transaction tracking</td></tr>
<tr><td><b>TLS/SSL</b></td><td>Protocol versions (1.0–1.3, SSL 3.0), handshake types (ClientHello, ServerHello, Certificate), content types</td></tr>
<tr><td><b>DHCP</b></td><td>Message types, IP assignments (client/server/gateway), transaction IDs</td></tr>
</table>

### Security Anomaly Detection

Statistical detectors, followed by 18 signatures and 10 stateful rules. Limits were calibrated on
measured phone traffic and are listed with their floors:

| Detector | Trigger | Severity |
|---|---|---|
| Port Scan | distinct destination ports from one app in 10 s (floor 8, default 20) | High |
| SYN Flood | SYN packets to one target per second (floor 50, default 100) | Critical |
| Distributed Flood | 300 packets per second at one target, half from distinct sources (HyperLogLog) | Critical |
| Connection Flooding | new connections from one app per second (100, three times that for a browser) | High |
| DNS Tunneling | 10 query names over 50 characters under one zone in 60 s | Medium |
| ARP Spoofing | IP-to-MAC binding changes, or one MAC claiming two addresses (root mode) | Critical |
| Malformed TCP | SYN set together with FIN or RST | Medium |

Detectors count per app where the platform names one (VPN mode, Android 10 and later), and per source
address otherwise, and alerts name the app. Detection that needs no decryption:

| Detector | Trigger | Severity |
|---|---|---|
| `APP-001` New TLS library | an app settled on its cipher lists presents a new one, from its JA4 fingerprint | Medium |
| `FLOW-001` Opaque flow | a first payload that looks uniformly random, on a port with no expected encryption | Medium |
| `FLOW-002` Protocol mismatch | a first payload on port 22, 53 or 80 that does not speak that port's protocol | Medium |
| `FLOW-003` Beacon | regular gaps between bursts, to an address no DNS name explains | Medium |
| `FLOW-004` TXT channel | 3 TXT answers of 100 bytes or more under one zone in 60 s | High |
| `FLOW-005` Failed lookups | 20 distinct names failing to resolve for one app in 60 s | Medium |

While capture runs in VPN mode, AndroNet refuses DNS over TLS and DNS over HTTPS to its tunnel resolvers,
so that Android falls back to plain DNS and names reach detection. **DNS therefore leaves the phone
unencrypted during capture.** A strict Private DNS server, if you chose one, is left alone, and the DNS
detectors then see nothing.

Measured accuracy, cost and energy, including what AndroNet misses, are in [`evaluation/`](evaluation/README.md).

Alerts surface instantly as in-app SnackBar notifications with severity, type, source IP, and description.

**Adaptive threshold engine:**
- 60-second calibration window on capture start (no false alerts during warm-up)
- Baselines derived from the 90th percentile of observed traffic — resistant to outlier spikes
- Exponential moving average (α = 0.05) keeps baselines current as traffic patterns evolve
- Samples that reach the threshold never train the baseline, so an attack cannot raise its own bar
- Ceilings are fixed when learning ends: the larger of the default and 4× the learned baseline
- Live threshold values visible under **Settings → Adaptive Thresholds**
- Status indicator shows amber (calibrating, with countdown) or green (actively monitoring)

**Entropy-based covert channel detection** (Shannon entropy on every payload ≥ 64 bytes):

| Signal | Threshold | Detects |
|---|---|---|
| DNS payload entropy | > 6.2 | dnscat2, iodine tunneling |
| ICMP echo payload entropy | > 6.0 | icmptunnel, ptunnel covert channels |
| Outgoing HTTP or DNS entropy | > 7.6 | Data exfiltration |
| Suspicious encoding | 7.2–7.6 | Flagged at medium severity |

Entropy score is displayed as a live badge (`E:x.x`) on each packet in the capture UI.

*False-positive mitigations:* 30-second per-source cooldown after an alert, a 5-packet consecutive-hit requirement (3 for DNS), a magic-byte pre-filter for common compressed/media formats (JPEG, PNG, ZIP, GZIP, BZ2, XZ, RAR, 7ZIP, MP4, WebM), an allowlist for legitimately high-entropy protocols, and no payload matching on encrypted ports.

### Traffic Statistics & Analytics

- Real-time packets/sec, bytes/sec, and active connection counts
- Protocol distribution charts and top-talkers by volume
- 60-second rolling bandwidth graph

### PCAP Export

- Standard pcapng format with nanosecond-resolution timestamps — natively readable by Wireshark and tshark
- Saved to `/sdcard/Download/AndroNet/`
- Size- and duration-based file rotation with automatic pruning of old captures

### Protocol Intelligence

Names **about 40 application protocols** by port and dissects HTTP, DNS, TLS, DHCP, QUIC, SIP, RTP, SMB and NTP, including HTTPS, DNS, SSH, FTP, SMTP, MySQL, PostgreSQL, MongoDB, Redis, SIP, RDP, and VNC. DNS-over-HTTPS is detected by TLS SNI against known public resolvers, surfacing a common technique for bypassing on-path DNS monitoring.

### Per-App Traffic Attribution

Every TCP/UDP flow is resolved to the installed app that owns it (via `ConnectivityManager.getConnectionOwnerUid`) and shown inline on each packet — visibility a desktop packet analyzer can't offer, since it isn't running on the device whose traffic it's inspecting.

### Interface

- **16 predefined, color-coded filters:** ALL, HTTP, HTTPS, DNS, TCP, UDP, TLS, QUIC, ICMP, DHCP, ARP, SSH, FTP, SMTP, POP3, IMAP
- Live packet counts per filter (e.g. `HTTP (25)`)
- Filters adapt to observed traffic and match on both transport and application layers
- Enriched DPI detail inline — HTTP URLs/methods/status, DNS queries, TLS SNI, DHCP addresses, resolved owning app
- Light, dark, and system-follow themes (Settings → Theme)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Flutter UI Layer                         │
│   Packet List Display │ Statistics Dashboard │ Anomaly Alerts   │
└──────────────────────────────┬────────────────────────────────-─┘
                                │ EventChannel / MethodChannel
                                ▼
┌───────────────────────────────────────────────────────────────-─┐
│                        MainActivity.kt                          │
│   Root detection & mode selection · Method handlers             │
│   EventChannel setup for packet streaming                       │
└───────────────┬───────────────────────────────┬─────────────────┘
                 ▼                               ▼
   ┌─────────────────────────┐    ┌─────────────────────────────┐
   │  ZdtunVpnService.kt     │    │  NetHunterService.kt         │
   │  (VPN Mode)             │    │  (Root Mode)                  │
   │  TUN mgmt · zdtun relay │    │  su helper, AF_PACKET         │
   │  PacketRecord builder   │    │  PacketRecord builder         │
   └────────────┬────────────┘    └───────────────┬───────────────┘
                 └───────────────┬─────────────────┘
                                  ▼
        ┌───────────────────────────────────────────────┐
        │     PacketAnalysisManager.kt (Orchestrator)    │
        │  Coordinates DPI, detection, stats, export      │
        └───┬──────────┬─────────────┬──────────┬────────┘
            ▼           ▼             ▼          ▼
         ┌─────┐   ┌─────────┐   ┌─────────┐  ┌────────┐
         │ DPI │   │ Anomaly │   │ Traffic │  │  PCAP  │
         │     │   │Detector │   │  Stats  │  │ Writer │
         └──┬──┘   └────┬────┘   └────┬────┘  └───┬────┘
            └───────────┴─────────────┴────────────┘
                                  ▼
        ┌───────────────────────────────────────────────┐
        │               Native Layer (C / JNI)           │
        │   zdtun_vpn.c │ capture_helper.c │ pcap_writer.c  │
        └───────────┬─────────────────────┬───────────────┘
                     ▼                     ▼
              ┌───────────┐         ┌────────────┐
              │  zdtun    │         │  AF_PACKET │
              │  library  │         │  socket    │
              └─────┬─────┘         └──────┬─────┘
                     └──────────┬───────────┘
                                 ▼
                  TUN / Network Interfaces
                  (wlan0, rmnet0, eth0, ...)
                                 ▼
                            Internet
```

---

## Installation

### Option 1 — Latest Release (Recommended)

1. Go to [Releases](../../releases)
2. Download `AndroNet-vX.Y.Z-arm64.apk`
3. Open the file on your Android device
4. Enable **Install from unknown sources** if prompted
5. Install and launch AndroNet

### Option 2 — Build from Source

**Requirements:** Flutter 3.44.0 · NDK 28.2.13676358 · Java 17

```bash
git clone --recurse-submodules https://github.com/amibhai/AndroNet.git
cd AndroNet
flutter pub get
flutter build apk --release --split-per-abi --target-platform android-arm64
```

Output: `build/app/outputs/flutter-apk/app-arm64-v8a-release.apk`

### Publishing a Release

```bash
# Windows
scripts/tag-release.ps1 1.0.0

# Linux/Mac
./scripts/tag-release.sh 1.0.0
```

### Build Requirements Reference

| Component | Version |
|---|---|
| Flutter | 3.44.0 stable |
| Dart SDK | 3.8.1+ |
| Android Gradle Plugin | 8.11.2 |
| Gradle Wrapper | 8.14.3 |
| Kotlin | 2.2.21 |
| NDK | 28.2.13676358 |
| compileSdk | 37 |
| targetSdk | 36 |
| minSdk | 24 (Android 7.0) |

> **16KB page alignment:** Android 15+ (API 35+) devices using 16KB memory pages require native libraries compiled with `-Wl,-z,max-page-size=16384` and packaged with `useLegacyPackaging = false`. Both flags are already applied to all `.so` targets (`zdtun_vpn`, `pcap_writer`, `pcap_capture`).

### Prerequisites

- Flutter SDK 3.44.0+
- Android Studio with NDK 28.2.13676358
- CMake 3.22.1+
- A rooted device (optional — required only for root mode)

---

## Usage

### VPN Mode (Unrooted)

1. Launch the app and grant VPN permission
2. Tap **Start Capture**
3. Internet connectivity continues normally while capturing

### Root Mode

1. A working `su` is detected at launch and selects this mode automatically
2. Grant root when your root manager asks
3. Tap **Start Capture**; the helper runs only for the duration of the capture

### Exporting PCAP

1. Tap **Export PCAP** during capture
2. Files save to `/sdcard/Download/AndroNet/`
3. Open directly in Wireshark for further analysis

---

## Performance

Measured on a Pixel 8 against PCAPdroid, with the method and limits in [`evaluation/`](evaluation/README.md).
The figures that matter are in the paper's evaluation section and in `evaluation/results/`. Root mode has
been exercised on a rootable emulator only.

---

## Technical Stack

| Layer | Technology |
|---|---|
| UI | Flutter 3.32.8, Dart 3.8.1 |
| Service | Kotlin 1.8, Coroutines |
| Native | C (JNI), CMake 3.22.1 |
| VPN Engine | zdtun |
| Root capture | AF_PACKET helper through `su` |

---

## Troubleshooting

### Quick log collection

```powershell
# Save the last crash log from a connected device
.\scripts\get-crash-log.ps1

# Stream live logs
.\scripts\get-crash-log.ps1 -Live
```

### APK fails to install

| Symptom | Fix |
|---|---|
| `INSTALL_FAILED_NO_MATCHING_ABIS` | Use the matching APK: `app-arm64-v8a-release.apk` (64-bit) or `app-armeabi-v7a-release.apk` (32-bit) |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Uninstall the existing build: `adb uninstall com.example.packet_analyzer` |
| App not appearing after sideload | Enable "Install from unknown sources" for your file manager app |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | APK wasn't signed — build with `flutter build apk`, not a raw assemble |

### App crashes on launch

Run `.\scripts\get-crash-log.ps1` and check for `FATAL EXCEPTION` or `AndroidRuntime`.

- **`UnsatisfiedLinkError`** — native `.so` missing for your ABI; download the correct APK variant
- **`ClassNotFoundException`** — MultiDex not initialized; ensure `minSdkVersion ≥ 23` and reinstall cleanly
- **Flutter rendering crash** — look for `ANDRONET FLUTTER ERROR` in the log

### Capture won't start / "VPN permission denied"

- Grant VPN permission when prompted; if the dialog never appears, enable it manually under **Settings → VPN → AndroNet**
- Tap **Start** only once — the button greys out ("Wait…") while the VPN negotiates
- If capture starts then immediately stops: `adb logcat | grep -E "ZdtunVpn|CaptureService|onCaptureError"`

### VPN mode shows no packets

```bash
adb logcat | grep -E "ZdtunVpn|CaptureService|AndroNet"
```

- Look for `startForeground` — if missing, the OS killed the service; update to the latest build
- Confirm the tunnel is active: **Settings → Network → VPN** should show "AndroNet VPN Active"
- Restart the app — the service recovers automatically on next launch

### Root mode issues

```bash
# On-device, requires root
su -c "id"                          # must return uid=0
adb logcat -s RootChecker NetHunterService   # says why the probe or the helper failed
```

- If root detection fails, some Magisk configurations hide root from apps — grant root to AndroNet explicitly in the Magisk app manager

### Android 15 — crashes with illegal instruction / alignment fault

Confirm you're on build ≥ 1.0 (16KB page-size alignment applied). If building yourself, verify `useLegacyPackaging = false` in `build.gradle` and that `android:extractNativeLibs` is absent from `AndroidManifest.xml`.

### Filing a bug report

```bash
adb bugreport bug-report.zip
```

Attach `bug-report.zip` when opening a GitHub issue.

---

## Roadmap

- [ ] Root mode on physical rooted hardware, which has only run on an emulator so far
- [ ] Cross-device portability testing across the NetHunter-supported device matrix
- [ ] Historical session storage and diffing between captures (sqflite is already a dependency, currently unused for this)
- [ ] In-app packet search across IP/domain/payload/app, beyond the existing protocol filters
- [ ] Custom detection rules authored from the UI (`RuleEngine.addRule`/`SignatureDatabase.addSignature` already support it programmatically; no UI path yet)
- [ ] Threat-intel IP/domain blocklist import, replacing the small hardcoded sample list
- [ ] CSV/JSON packet export alongside PCAP
- [ ] Real traffic-over-time and anomaly-frequency charts (fl_chart is already a dependency, currently underused)

---

## Team CipherSec

| Name |
|---|
| Ritik |
| Syed Misbah Uddin |
| Kamal Akhter |
| Swastik |

---

## Contributing

Contributions are welcome. Please fork the repository, create a feature branch, and open a pull request with a clear description of the change and testing performed. For larger changes, open an issue first to discuss the approach.

---

## Acknowledgments

- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) — inspiration for the zdtun integration approach
- [zdtun](https://github.com/emanuele-f/zdtun) — packet tunneling library by @emanuele-f
- [Wireshark](https://www.wireshark.org/) — protocol reference
- Kali NetHunter — target platform

---

## License

MIT License — see [LICENSE](LICENSE) for details.
