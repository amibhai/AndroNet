# AndroNet evaluation

Everything behind the numbers in the paper. Result files are in `results/`, and
`paper/build_paper.py` fills the paper from them, so each published figure traces to a file here.

## What was measured, and where

| Experiment | Runs on | Script |
|---|---|---|
| Second held-out set: frozen v1.4.0 and v1.5.0 on captures unopened until the freeze, then v1.5.1 | Pixel 8 under ART, with identical desktop JVM verdicts | `scripts/second_cycle.sh replay` (or its `host` and `phone` halves), `scripts/run_replay.py`, `scripts/score.py --fresh` |
| The same captures through Suricata 8.0.7 and the ET Open rules, as a yardstick | desktop | `scripts/suricata_baseline.py` |
| Whether each alert on those captures is about the attack, and why the trojans it missed got away | capture files, tshark | `scripts/flow_check.py`, `scripts/rat_misses.py` |
| Whether a quiet TCP connection survives the tunnel: no capture, v1.5.0, v1.5.1, PCAPdroid | Pixel 8, emulator | `scripts/idle_probe.py` |
| What app identity adds: the same build with it switched off | Pixel 8 | `scripts/benign_session.py --no-identity`, `scripts/live_attacks.py --no-identity` |
| Everyday use over days, counts only, with crash, restart and reboot checks at collection | Pixel 8 and Oppo A53, each in its owner's hands | `scripts/soak.py` |
| Whether capture outlives Android's daily limit on its service type: v1.5.1 against v1.5.2, with the limit cut to five minutes | Pixel 8 | `scripts/fgs_limit_check.py` |
| JA3 and JA4 against Wireshark, and how much JA4 varies within a library | captures, tshark | `scripts/check_fingerprints.py`, `scripts/fingerprint_variety.py` |
| Held-out accuracy of v1.3.0 and v1.4.0 | v1.4.0 on the Pixel 8 under ART, with identical desktop JVM verdicts. v1.3.0 on the desktop JVM, with verdicts matching the phone on the 35 traces it can finish there | `scripts/run_replay.py`, `scripts/score.py` |
| Live attacks through the real VPN path | Pixel 8, and further phones where listed in `results/device_*.json` | `scripts/live_attacks.py` |
| Live benign browsing with alert counting and pcapng export | Pixel 8, and further phones where listed in `results/device_*.json` | `scripts/benign_session.py` |
| Rooted path end to end | rootable Android 16 emulator, `su` stand-in | `scripts/rooted_experiment.py` |
| What a VPN cannot see (real nmap against the phone) | Pixel 8 and lab laptop | `scripts/visibility_probe.py` |
| Per-layer cost on each core class | Pixel 8 under ART | `scripts/run_cost.py` |
| Throughput, latency, CPU, memory vs PCAPdroid | Pixel 8 | `scripts/throughput_final.py` |
| Whole-device power vs PCAPdroid | Pixel 8 on battery | `lab/energy.sh`, `scripts/energy_start.py` |
| The cause of each held-out miss and of the largest false alarm groups | capture files, tshark | `scripts/analyse_misses.py` |
| What benign development traffic reached, behind each limit | development captures | `scripts/calibrate.py` |
| How much of v1.3.0's rule cost its regex end wildcards explain (kept here; the paper no longer reports it) | Pixel 8 under ART | `scripts/build_harness.py baseline_nowild`, `scripts/run_cost.py` |

## Method

**Split.** The development set informed every correction and every limit. The held-out set was
fixed before any detector saw it. Its ground truth is in `scripts/test_manifest.py`, written
in advance from each capture's published description. The code was then frozen
(`results/freeze.json`) and held-out results were never used to change it. Three amendments are
recorded there: the root helper's process cleanup, the pcapng writer and the session script below,
none of which touches detection code. `scripts/analyse_misses.py` explains misses after the fact
and feeds nothing back.

**Second cycle.** New detectors can only be validated on new data, and the first held-out set had been
seen, so it became development data for v1.5.0. The new set was selected by a rule stated in
`scripts/test_manifest_v2.py`, from names and publishers' descriptions, and its ground truth was
written before any capture was opened. `scripts/fetch_fresh.py` downloads it (pcaps only, never the
trojans' APKs) and `results/fresh_set.json` holds its hashes. `scripts/freeze_v15.py` then recorded the
sources and builds, and `--check` confirms nothing changed since. Frozen v1.4.0 and v1.5.0 replay the
same set, so the comparison is on data neither saw. Files that v1.5.0 runs would overwrite are kept in
`results/v140/`, for the v1.4.0 paper at git tag `v1.4.0-paper`.

**The flow check and version 1.5.1.** Capture recall accepts an expected alert anywhere in a capture, and
the trojan captures come from phones in everyday use. So after the frozen run, `scripts/flow_check.py`
read the packet behind every alert. It took v1.5.0 from 14 of 24 captures to 11 and left v1.4.0 at 7. Eleven
`FLOW-003` alerts pointed at web services: a connection outlived the five-minute DNS entry for its address,
which then read as unnamed. That defect and two others found afterwards (zdtun resetting quiet TCP
connections, an owner cache keyed by local port alone) are fixed in v1.5.1, recorded as an amendment in
`results/freeze_v15.json`. The frozen hashes and builds stay, in `build/current`, `build/v150` and the
`andronet-eval-*-v150.apk` files. The v1.5.0 column remains the unseen test. The fresh captures produced the
beacon fix, so they cannot test v1.5.1; the phone sessions and real use recorded after the fix can.

**A lab fault.** The laptop has two adapters on the test network. The lab DNS server used a wildcard socket,
so Windows chose each answer's source address by interface metric, which it moves with link speed, and the
phone's connected UDP socket would drop an answer from the other address. `lab/live_servers.py` now answers
from the address asked.

**A collection fault.** The first version of `benign_session.py` kept only the first rotated export
of each phone session. So the limits were set on the first 131 s of the 391 s development session,
and the first held-out replay covered 110 s of the 523 s test session. Found after the held-out
results. The whole test session was then replayed on all builds (`scripts/merge_session_replay.py`),
and it raised the same three alerts as the live run. Over its whole length the development session
exceeds two limits (126 destinations per 10 s against 100, 118 new connections per second against
60). Those limits were left as frozen, because the held-out results had already been seen.

**A false start.** The first long run on the Pixel 8 began on Nov 4 at 16:59 and ended cleanly after 35 minutes,
with no crash or restart (`results/soak_pixel_nov4.json`). A clean end means the service was told to stop: the VPN
was switched off, another VPN app took over, the app's stop control was used, or Android ended the service. Android 15
and later allow a `dataSync` foreground service, the type v1.5.1 declares for its VPN service, six hours a day, and
the phone had run many tests that day, but nothing on the phone settles which it was. The end was found only on Nov 6,
and the run was restarted then with profiles emptied, alongside the Oppo's.

**Version 1.5.2.** The restarted run did end at that limit. On Nov 7 at 08:23, after 11 hours of the phone's day and
6.0 hours of the app's running time, Android crashed the app with `ForegroundServiceDidNotStopInTimeException`
(`results/soak_pixel_crashes.json`). Version 1.5.2 declares both capture services as special-use foreground services,
which have no such limit, and changes nothing else; `results/freeze_v15.json` records it as an amendment.
`scripts/fgs_limit_check.py` cuts the limit to five minutes with `device_config`, runs one build past it and restores
the setting: `results/fgs_limit_v151.json` and `results/fgs_limit_v152.json`. The Oppo runs Android 12, which has no
such limit. The fix has not yet had a day-long run of its own.

**The Oppo's run** ended after 29.7 hours, when the phone restarted overnight to install a system update
(`results/soak_oppo_reboot.json`: boot reason `reboot,ota`, build F.31 to F.32). The app does not start capture by
itself at boot, so capture did not resume. All 16 of its beacon-test alerts came from one app, about once an hour; the
published results keep only how alerts spread across apps, and the names stay in `results/private/`.

**Replay.** `scripts/build_harness.py` compiles the production Kotlin sources into a desktop jar
and an Android dex, with one mechanical change: `System.currentTimeMillis()` becomes a settable
clock, so sliding windows follow trace time and a replay gives the same answer at any speed. On
the phone the dex runs under `app_process`, so it uses ART and the ICU regular expression engine.
For v1.3.0 the sources come from git commit `93d058f`. Its packet parser lived inside an Android
service, so `harness/pipeline_baseline/` holds a verbatim copy of that code.

**Cost.** The production code carries no timers. Layers are costed by ablation: the same trace is
replayed with the signature and rule lists emptied by reflection.

**Provenance of development traces**, recorded per trace in `traces/dev/manifest.json`:
- `tool`: the real tool ran and tshark captured it (nmap 7.92, sqlmap).
- `socket`: real sockets speak the attack protocol to a local endpoint. Nikto is in this group
  because the lab laptop's antivirus blocks `nikto.pl`, so its documented request shape is replayed.
- `crafted`: frames written with scapy, for packets a desktop socket cannot emit.

## Sources of third-party captures

First cycle: the [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures), the capture files of
Chris Sanders' [Practical Packet Analysis](https://github.com/chrissanders/packets),
[StopDDoS](https://github.com/StopDDoS/packet-captures), Samir Bousseaden's
[PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK), the [Zeek](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)
and [Suricata](https://github.com/OISF/suricata-verify) test suites, the
[tcpreplay sample captures](https://tcpreplay.appneta.com/wiki/captures.html), and a WannaCry capture by
David Szili on [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2017/05/18/index2.html).
Second cycle: the [Android Mischief dataset](https://doi.org/10.17632/xbx2j63xfd.1) by Kamila Babayeva, StopDDoS
and PCAP-ATTACK. `scripts/test_manifest.py` and `scripts/test_manifest_v2.py` name each capture's publisher, and
`scripts/fetch_traces.py`, `scripts/fetch_extra.py` and `scripts/fetch_fresh.py` hold its address.

## Limits worth knowing before citing these numbers

- Scripted browsing lasting minutes on one network, and everyday use of two phones over a few days. Other apps and
  networks will differ.
- The rooted path ran on an emulator with a stand-in for `su`, never on physical rooted hardware.
- Power comes from the phone's fuel gauge at 1 Hz, which is coarser than an external power monitor.
- PCAPdroid's paid blocklist feature was not tested.
- `15 Mbit/s` for the pre-fix tunnel was measured on a build that already had the detection
  corrections but still drove zdtun from two coroutines. It is not a clean v1.3.0 measurement.
- Throughput rounds that ran while the lab laptop was busy with other work were discarded and
  repeated (`results/superseded/`, local only). The laptop serves the transfers, so its load shows
  up as lost throughput on the phone. Keep it idle during `throughput_final.py`.
- `atk_dnstunnel_remoteshell` was labelled a DNS channel from its published name and turned out to
  be a cleartext shell on TCP port 53. The label stayed as written in advance, so it counts as a miss.

## Reproducing

```bash
python scripts/fetch_traces.py                 # third-party captures
python scripts/fetch_extra.py <dir>            # archived captures; WannaCry stays outside the repo
python lab/gen_dev_traces.py --phone <ip> --local <laptop-ip>
python scripts/build_harness.py baseline
python scripts/build_harness.py current
python scripts/build_harness.py v151
flutter build apk --release --target-platform android-arm64 \
    --dart-define=ANDRONET_EVAL=true --android-project-arg=andronetAutomation=true
python lab/live_servers.py                     # keep running during live experiments
python scripts/run_replay.py --build current --set test --where phone --view root
python scripts/fetch_fresh.py D:/andronet_eval/fresh   # the second cycle's captures, where second_cycle.sh looks
sh scripts/second_cycle.sh replay              # its replays; the script lists the other blocks
```

Only scan and flood hosts you own. Every script here targets the lab machine, its loopback, or
the phone it is pointed at. `rooted_experiment.py` refuses to run on anything but an emulator
because it disables SELinux enforcement.

## Private data

`results/private/` holds pcapng exports of browsing on the test phone. It is excluded from git and
stays on the machine that made it. `results/` keeps aggregate counts only.
