# AndroNet evaluation

Everything behind the numbers in the paper. Result files are in `results/`, and
`paper/build_paper.py` fills the paper from them, so each published figure traces to a file here.

## What was measured, and where

| Experiment | Runs on | Script |
|---|---|---|
| Held-out accuracy of v1.3.0 and v1.4.0 | v1.4.0 on the Pixel 8 under ART, with identical desktop JVM verdicts. v1.3.0 on the desktop JVM, with verdicts matching the phone on the 35 traces it can finish there | `scripts/run_replay.py`, `scripts/score.py` |
| Live attacks through the real VPN path | Pixel 8 | `scripts/live_attacks.py` |
| Live benign browsing with alert counting and pcapng export | Pixel 8 | `scripts/benign_session.py` |
| Rooted path end to end | rootable Android 16 emulator, `su` stand-in | `scripts/rooted_experiment.py` |
| What a VPN cannot see (real nmap against the phone) | Pixel 8 and lab laptop | `scripts/visibility_probe.py` |
| Per-layer cost on each core class | Pixel 8 under ART | `scripts/run_cost.py` |
| Throughput, latency, CPU, memory vs PCAPdroid | Pixel 8 | `scripts/throughput_final.py` |
| Whole-device power vs PCAPdroid | Pixel 8 on battery | `lab/energy.sh`, `scripts/energy_start.py` |
| The cause of each held-out miss and of the largest false alarm groups | capture files, tshark | `scripts/analyse_misses.py` |
| What benign development traffic reached, behind each limit | development captures | `scripts/calibrate.py` |
| How much of v1.3.0's rule cost its regex end wildcards explain | Pixel 8 under ART | `scripts/build_harness.py baseline_nowild`, `scripts/run_cost.py` |

## Method

**Split.** The development set informed every correction and every limit. The held-out set was
fixed before any detector saw it. Its ground truth is in `scripts/test_manifest.py`, written
in advance from each capture's published description. The code was then frozen
(`results/freeze.json`) and held-out results were never used to change it. Three amendments are
recorded there: the root helper's process cleanup, the pcapng writer and the session script below,
none of which touches detection code. `scripts/analyse_misses.py` explains misses after the fact
and feeds nothing back.

**A collection fault.** The first version of `benign_session.py` kept only the first rotated export
of each phone session. So the limits were set on the first 131 s of the 391 s development session,
and the first held-out replay covered 110 s of the 523 s test session. Found after the held-out
results. The whole test session was then replayed on all builds (`scripts/merge_session_replay.py`),
and it raised the same three alerts as the live run. Over its whole length the development session
exceeds two limits (126 destinations per 10 s against 100, 118 new connections per second against
60). Those limits were left as frozen, because the held-out results had already been seen.

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

## Limits worth knowing before citing these numbers

- One phone, one network, scripted browsing lasting minutes. Real use across days and apps will differ.
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
flutter build apk --release --target-platform android-arm64 \
    --dart-define=ANDRONET_EVAL=true --android-project-arg=andronetAutomation=true
python lab/live_servers.py                     # keep running during live experiments
python scripts/run_replay.py --build current --set test --where phone --view root
```

Only scan and flood hosts you own. Every script here targets the lab machine, its loopback, or
the phone it is pointed at. `rooted_experiment.py` refuses to run on anything but an emulator
because it disables SELinux enforcement.

## Private data

`results/private/` holds pcapng exports of browsing on the test phone. It is excluded from git and
stays on the machine that made it. `results/` keeps aggregate counts only.
