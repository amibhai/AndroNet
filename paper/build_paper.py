#!/usr/bin/env python3
"""Fills andronet.template.tex from evaluation/results/ and compiles the camera-ready PDF.

Every measured number in the paper comes from this script's reads. A value that has not been
measured yet stays visible in the PDF as a marked gap, and `--final` refuses to build at all if any
gap or any author placeholder remains, so an estimate can never slip through. A sentence that states
a measured fact has a check here that stops the build if a new result contradicts it.
"""
import argparse
import collections
import csv
import datetime
import json
import pathlib
import re
import shutil
import statistics as st
import subprocess
import sys
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE.parent / "evaluation" / "results"
sys.path.insert(0, str(HERE.parent / "evaluation" / "scripts"))
from test_manifest import ATTACKS  # noqa: E402
from test_manifest_v2 import ATTACKS as FRESH  # noqa: E402
import score as scorer  # noqa: E402

TEX = pathlib.Path(r"D:\andronet_eval\TinyTeX\bin\windows")
TEMPLATE = HERE / "andronet.template.tex"
OUT = HERE / "andronet.tex"
ZIP_FILES = ["andronet.tex", "andronet.bib", "andronet.bbl", "llncs.cls", "splncs04.bst",
             "fig_architecture.pdf", "fig_architecture.tex", "DescriptionTexts.txt"]
WORDS = {0: "no", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
         11: "eleven", 12: "twelve"}

values = {}
missing = []
FINAL = False
REPLAY_WHERE = "phone"


def need(path):
    p = RESULTS / path
    if not p.exists():
        missing.append(path)
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def fmt_int(n):
    return f"{int(round(n)):,}".replace(",", "{,}")


def pct(x, digits=1):
    return f"{100 * x:.{digits}f}"


def word(n):
    return WORDS.get(n, str(n))


def first_cycle():
    """The first held-out set: frozen v1.3.0 and v1.4.0, then v1.5.0 with this set as development data."""
    base = need("accuracy_baseline_test_host.json")
    cur = need("accuracy_current_test_phone.json")
    if not base or not cur:
        return
    b = scorer.score(base)
    c = scorer.score(cur)
    bb, cb = b["benign"], c["benign"]
    v = values
    v["ATK_TOTAL"] = str(len(ATTACKS))
    v["C_RECALL_D"], v["C_RECALL_T"] = str(c["recall"]["detected"]), str(c["recall"]["total"])
    v["B_RECALL_D"], v["B_RECALL_T"] = str(b["recall"]["detected"]), str(b["recall"]["total"])
    v["C_FPR"] = pct(cb["packetFPR"], 3)
    v["B_FPR"] = pct(bb["packetFPR"], 1)
    v["C_BEN_ALERTS"], v["B_BEN_ALERTS"] = fmt_int(cb["alerts"]), fmt_int(bb["alerts"])
    v["BENIGN_PKTS_M"] = f"{cb['packets'] / 1e6:.2f}"

    phone_c = cb["perTrace"]["benign_phone_test_00"]
    phone_b = bb["perTrace"]["benign_phone_test_00"]
    v["B_PHONE_FLAG"] = f"{100 * phone_b['flagged'] / phone_b['packets']:.1f}"
    v["C_PHONE_FLAG"] = f"{100 * phone_c['flagged'] / phone_c['packets']:.3f}"
    v["B_RULE7"] = fmt_int(phone_b["alerts"].get("RULE-007", 0))
    ssh = bb["perTrace"]["benign_ssh_zeek"]
    v["B_SSH_FLAG"] = f"{100 * ssh['flagged'] / ssh['packets']:.0f}"

    def total(runs, prefix):
        return sum(n for name, n in runs if name.startswith(prefix))
    runs = [(run["name"], sum(l["packets"] for l in run["labels"].values())) for run in cur["runs"]]
    v["TEST_ATK_PKTS"] = fmt_int(total(runs, "atk_"))
    v["TEST_PHONE_PKTS"] = fmt_int(total(runs, "benign_phone"))
    v["TEST_BEN_PKTS"] = fmt_int(total(runs, "benign_") - total(runs, "benign_phone"))
    v["TEST_BEN_N"] = str(sum(1 for n, _ in runs if n.startswith("benign_") and not n.startswith("benign_phone")))

    new = need("accuracy_v15_dev_host.json")
    newer = need("accuracy_v151_dev_host.json")
    if not new or not newer:
        return
    d = scorer.score(new)
    for tag, s in (("D15", d), ("D151", scorer.score(newer))):
        sb = s["benign"]
        v[f"{tag}_RECALL_D"] = str(s["recall"]["detected"])
        v[f"{tag}_FPR"] = pct(sb["packetFPR"], 3)
        v[f"{tag}_BEN_ALERTS"] = fmt_int(sb["alerts"])
        phone_d = sb["perTrace"]["benign_phone_test_00"]
        v[f"{tag}_PHONE_FLAG"] = f"{100 * phone_d['flagged'] / phone_d['packets']:.3f}"
    db = d["benign"]
    v["D15_BIG_FP"] = fmt_int(sum(db["perTrace"]["benign_bigFlows"]["alerts"].values()))

    def caught(s):
        return {k for k, r in s["captures"].items() if r["detected"]}
    if caught(c) - caught(d):
        raise SystemExit(f"v1.5.0 lost first-cycle detections: {caught(c) - caught(d)}")
    if {"atk_icmp_flood_large", "atk_arp_poison", "atk_dnstunnel_remoteshell", "atk_dnstunnel_txt_c2"} - caught(d):
        raise SystemExit("the first-cycle paragraph says v1.5.0 catches the misses it names")
    still = set(d["captures"]) - caught(d)
    if still != {"atk_nmap_version_zeek", "atk_meterpreter_rdp_tunnel"}:
        raise SystemExit(f"the first-cycle paragraph names other misses than {still}")


def second_cycle():
    """Frozen v1.4.0 and v1.5.0 on captures that nothing had opened before the freeze."""
    v = values
    v["F_TOTAL"] = str(len(FRESH))
    scoped = {k: m for k, m in FRESH.items() if m["expect"]}
    untargeted = [k for k, m in FRESH.items() if not m["expect"]]
    classes = {}
    for k, m in scoped.items():
        classes.setdefault(m["class"], []).append(k)
    v["F_T"] = str(len(scoped))
    v["F_RAT_T"] = str(len(classes["android_rat"]))
    v["F_FLOOD_T"] = str(len(classes["flood"]))
    v["F_UNTARGETED"] = str(len(untargeted))
    v["F_OTHER_N"] = str(len(classes["flood"]) + len(classes["dga_backdoor"]))

    # Phone replays are what the paper reports; until they exist a draft shows the desktop ones, which
    # the parity check below requires to be identical
    where = "phone" if (RESULTS / "accuracy_v15_fresh_phone.json").exists() or FINAL else "host"
    if where == "phone" and not FINAL:
        ph, ho = optional("accuracy_v15_fresh_phone.json"), optional("accuracy_v15_fresh_host.json")
        if ho and {r["name"] for r in ph["runs"]} != {r["name"] for r in ho["runs"]}:
            print("note: the phone replays lag the desktop ones, so this draft shows the desktop results")
            where = "host"
    global REPLAY_WHERE
    REPLAY_WHERE = where
    new = need(f"accuracy_v15_fresh_{where}.json")
    old = need(f"accuracy_v140_fresh_{where}.json")
    fixed = need(f"accuracy_v151_fresh_{where}.json")
    if not new or not old or not fixed:
        return
    n, o, f = scorer.score(new, FRESH), scorer.score(old, FRESH), scorer.score(fixed, FRESH)
    if {n["recall"]["total"], o["recall"]["total"], f["recall"]["total"]} != {len(scoped)}:
        raise SystemExit("a fresh capture is missing from the replay")

    flows = {"F15": need(f"flow_check_v15_fresh_{where}.json"), "F14": need(f"flow_check_v140_fresh_{where}.json"), "F151": need(f"flow_check_v151_fresh_{where}.json")}
    if not all(flows.values()):
        return
    for tag, s in (("F15", n), ("F14", o), ("F151", f)):
        b = s["benign"]
        checked = flows[tag]
        if any(r["unmatched"] for r in checked["captures"].values()):
            raise SystemExit("an alert could not be traced to a packet")
        if {k: r["capture"] for k, r in checked["captures"].items()} != {k: r["detected"] for k, r in s["captures"].items()}:
            raise SystemExit("the flow check and the scorer disagree on capture-level hits")
        v[f"{tag}_CAPTURE_D"] = str(s["recall"]["detected"])
        v[f"{tag}_D"] = str(sum(r["flow"] for r in checked["captures"].values()))
        for key, cls in (("RAT", "android_rat"), ("FLOOD", "flood"), ("DGA", "dga_backdoor")):
            v[f"{tag}_{key}_D"] = str(checked["byClass"][cls]["flow"])
        v[f"{tag}_OFF"] = fmt_int(checked["alertsElsewhere"])
        v[f"{tag}_UNT"] = fmt_int(sum(sum(r["alerts"].values()) for r in s["untargeted"].values()))
        v[f"{tag}_BEN_ALERTS"] = fmt_int(b["alerts"])
        v[f"{tag}_FPR"] = pct(b["packetFPR"], 4)
        total = checked["alertsOnAttack"] + checked["alertsElsewhere"] + b["alerts"]
        v[f"{tag}_PRECISION"] = f"{100 * checked['alertsOnAttack'] / total:.1f}"

    # What the second-cycle paragraphs state about these results
    c15, c14, c151 = (flows[t]["captures"] for t in ("F15", "F14", "F151"))
    def off_beacons(c):
        return sum(r["elsewhere"].get("FLOW-003", 0) for r in c.values())
    chance = [k for k, r in c15.items() if r["capture"] and not r["flow"]]
    v["F15_BEACON_OFF"] = str(off_beacons(c15))
    v["F15_BEACON_OFF_CAP"] = word(off_beacons(c15)).capitalize()
    v["F15_CHANCE_WORD"] = word(len(chance))
    if off_beacons(c151) or {k for k, r in c151.items() if r["flow"]} != {k for k, r in c15.items() if r["flow"]}:
        raise SystemExit("the paragraph says the fix removes every such alert and keeps every detection")
    if any(k not in classes["android_rat"] or set(c15[k]["elsewhere"]) - {"FLOW-003", "RULE-007"} for k in chance):
        raise SystemExit("the paragraph says the chance hits were beacon alerts on trojan captures")
    if {k for k, r in c14.items() if r["capture"] and not r["flow"]}:
        raise SystemExit("the paragraph says the check leaves version 1.4.0 where it was")
    rule_only = [k for k in classes["flood"] if c14[k]["flow"] and "RULE-010" in c14[k]["onAttack"] and not {"L1:SYN_FLOOD", "L1:DISTRIBUTED_FLOOD", "L1:CONNECTION_FLOOD"} & set(c14[k]["onAttack"])]
    if len(rule_only) != 5 or int(v["F14_FLOOD_D"]) != 6:
        raise SystemExit("the paragraph says five of six flood hits came from the ICMP tunnel rule")
    lost = [k for k in classes["flood"] if c14[k]["flow"] and not c15[k]["flow"]]
    gained = [k for k in classes["flood"] if c15[k]["flow"] and not c14[k]["flow"]]
    v["F_FLOOD_LOST_WORD"] = word(len(lost))
    v["F_FLOOD_GAINED_WORD"] = word(len(gained))
    if set(lost) - set(rule_only):
        raise SystemExit("the paragraph says the floods lost were ICMP tunnel rule hits")
    if any(not {"L1:DISTRIBUTED_FLOOD"} & set(c15[k]["onAttack"]) for k in gained):
        raise SystemExit("the paragraph says the distributed-flood detector made the gain")
    hits = {k for k, r in c15.items() if r["flow"] and k in classes["android_rat"]}
    if {k for k in hits if "FLOW-001" in c15[k]["onAttack"]} != {"atk_fresh_rat_androidtester", "atk_fresh_rat_spymax"} or hits - {"atk_fresh_rat_androidtester", "atk_fresh_rat_spymax"} != {"atk_fresh_rat_saefko"} or "C2-003" not in c14["atk_fresh_rat_saefko"]["onAttack"]:
        raise SystemExit("the paragraph names other trojan hits")
    v["F_DGA_PKTS"] = str(sum(sum(l["packets"] for l in run["labels"].values()) for run in new["runs"] if run["name"] == "atk_fresh_c2_foudre_dga"))
    if int(v["F15_UNT"]) or int(v["F14_UNT"]):
        raise SystemExit("the paragraph says neither version alerts on the Windows-domain captures")

    def packets(result, names):
        return sum(sum(l["packets"] for l in run["labels"].values()) for run in result["runs"] if run["name"] in names)
    v["F_RAT_PKTS"] = fmt_int(packets(new, classes["android_rat"]))
    v["F_OTHER_PKTS"] = fmt_int(packets(new, classes["flood"] + classes["dga_backdoor"]))
    v["F_UNT_PKTS"] = fmt_int(packets(new, untargeted))
    v["F_BEN_PKTS"] = fmt_int(n["benign"]["packets"])
    v["F_SESSIONS"] = str(len(n["benign"]["perTrace"]))

    host = need("accuracy_v15_fresh_host.json")
    host_fixed = need("accuracy_v151_fresh_host.json")
    if host and host_fixed and where == "phone":
        def tab(r):
            return {run["name"]: {k: (x["packets"], x["flagged"]["any"], x["alerts"]) for k, x in run["labels"].items()} for run in r["runs"]}
        a = tab(host)
        if a != tab(new) or tab(host_fixed) != tab(fixed):
            raise SystemExit("phone and desktop verdicts differ; the Harness paragraph no longer holds")
        v["PARITY_TRACES"] = str(len(a))
        v["PARITY_PKTS"] = fmt_int(sum(x[0] for run in a.values() for x in run.values()))


def yardstick():
    """Suricata over the fresh set, read the same way as the flow check."""
    s = need("suricata_baseline.json")
    checked = need("flow_check_v15_fresh_host.json")
    if not s or not checked:
        return
    v = values
    cap = s["captures"]
    v["SUR_RULES"] = fmt_int(s["rules"])
    v["SUR_D"] = str(s["recallOnAttack"])
    v["SUR_FLOOD"] = str(s["byClass"]["flood"]["onAttack"])
    rats = {k for k, r in cap.items() if r.get("class") == "android_rat" and r["onAttack"]}
    if rats != {"atk_fresh_rat_ahmyth", "atk_fresh_rat_saefko"} or not cap["atk_fresh_c2_foudre_dga"]["onAttack"]:
        raise SystemExit("the yardstick paragraph names other Suricata hits")
    if not any("AhMyth" in sig for sig in cap["atk_fresh_rat_ahmyth"]["onAttackSignatures"]) or not any("Foudre" in sig for sig in cap["atk_fresh_c2_foudre_dga"]["onAttackSignatures"]):
        raise SystemExit("the yardstick paragraph says Suricata's rules name these two")
    ours = {k for k, r in checked["captures"].items() if r["flow"] and r["class"] == "android_rat"}
    v["SUR_UNION_WORD"] = word(len(rats | ours))
    v["SUR_UNION"] = str(len(rats | ours))
    if len(ours - rats) != 2:
        raise SystemExit("the yardstick paragraph says the first-payload test adds two trojans")
    reputation = re.compile(r"Listed Traffic|Poor Reputation|^ET (DROP|CINS|COMPROMISED|DSHIELD|Threatview|3CORESec|TOR)")
    floods = {k: r for k, r in cap.items() if r.get("class") == "flood" and r["onAttack"]}
    v["SUR_REP_WORD"] = word(sum(all(reputation.search(sig) for sig in r["onAttackSignatures"]) for r in floods.values()))
    if sum(any("DOS" in sig or "DDoS" in sig for sig in r["onAttackSignatures"]) for r in floods.values()) != 1:
        raise SystemExit("the yardstick paragraph says one flood hit comes from a rule that names a denial of service")
    benign = {k: r for k, r in cap.items() if k.startswith("benign_")}
    v["SUR_BEN"] = fmt_int(sum(r["alerts"] for r in benign.values()))
    if any(not sig.startswith("ET INFO") for r in benign.values() for sig in r["signatures"]):
        raise SystemExit("the yardstick paragraph says Suricata's alerts on the phone session are informational")


def live_text():
    """The sentences around the live runs, each checked against the result files."""
    v = values
    a = need("live_attacks_v151final.json")
    frozen = need("live_attacks_v15final.json")
    repeats = need("live_attacks_v151lookups.json")
    if a:
        lines = (RESULTS / "live_attacks_v151final.logcat").read_text(encoding="utf-8", errors="replace").splitlines()
        alerts = list(dict.fromkeys(line.strip() for line in lines if "ANOMALY" in line))
        apps = [re.search(r"\(app: ([^)]*)\)\s*$", line) for line in alerts]
        if not all(apps):
            raise SystemExit("the live paragraph says every alert names an app")
        others = sum(m.group(1) != "Shell" for m in apps)
        if others > 3:
            raise SystemExit("the live paragraph says few alerts named an app other than the attacker")
        v["LIVE_APP_TEXT"] = (f"all {len(alerts)} alerts named an app: the attacking process in {len(alerts) - others}, "
                              + (f"and an unrelated app that APP-001 flagged in {word(others)}." if others else "and no other."))
    if a and frozen and repeats:
        failed = [s["scenario"] for s in frozen["scenarios"] if not s["detected"]]
        if failed != ["dns_failed_lookups"] or frozen["detected"] != 27:
            raise SystemExit("the live paragraph describes one miss in the frozen run")
        hits = sum(s["detected"] for s in repeats["scenarios"])
        v["LIVE_MISS_TEXT"] = (f"Frozen version 1.5.0 detected {frozen['detected']}, raising no alert for failed lookups, which needs answers from the lab's DNS server. "
                               f"The laptop has two adapters on the network, so that server's answers could leave from an address the phone would reject. Once it answered from the address asked, the scenario fired in {hits} of {len(repeats['scenarios'])} runs, "
                               "though we cannot show that this caused the miss.")


def idle_text():
    v = values
    results = {tag: need(f"idle_probe_{name}.json") for tag, name in (("none", "pixel_none"), ("old", "pixel_v150"), ("new", "pixel_v151"), ("pd", "pixel_pcapdroid"), ("emu", "emu_v151_vpn"))}
    if not all(results.values()):
        return

    def survives(result):
        return {c["idleSeconds"]: c["secondBack"] for c in result["cases"]}
    none, old, new, pd, emu = (survives(results[t]) for t in ("none", "old", "new", "pd", "emu"))
    if not (all(none.values()) and all(new.values()) and all(emu.values()) and old[30] and pd[30] and not old[90] and not pd[90] and not old[300] and not pd[300]):
        raise SystemExit("the idle paragraph no longer matches its results")
    v["IDLE_TEXT"] = ("Quiet connections separate the relays. We opened a TCP connection through each tool, stayed silent, then sent a line and waited for its echo. "
                      f"With no capture and through version 1.5.1 the connection survives {max(new)}~s of silence, and {max(emu)}~s on the emulator. "
                      "Through version 1.5.0 and PCAPdroid, which also relays with zdtun, it is dead by 90~s, and an app holding one open for push messages has to reconnect.")


def identity_text():
    v = values
    on = need("benign_live_fresh_pixel.json")
    off = need("benign_live_fresh_pixel_noid.json")
    replay = need(f"accuracy_v15_fresh_{REPLAY_WHERE}.json")
    a = need("live_attacks_v151final.json")
    b = need("live_attacks_v151noid.json")
    if not (on and off and replay and a and b):
        return
    # The other phones' sessions, live with identity and replayed without it, on the same version
    second = ""
    fixed = need(f"accuracy_v151_fresh_{REPLAY_WHERE}.json")
    others = [p.stem.split("_", 1)[1] for p in sorted(RESULTS.glob("device_*.json")) if p.stem != "device_pixel"]
    if fixed and others:
        per_trace = scorer.score(fixed, FRESH)["benign"]["perTrace"]
        live_runs = [optional(f"benign_live_fresh_{t}.json") for t in others]
        if all(live_runs) and all(f"benign_fresh_{t}" in per_trace for t in others):
            if any(sum(r["alerts"].values()) for r in live_runs):
                raise SystemExit("the identity paragraph says the other phones' live sessions raised no alerts")
            replayed = collections.Counter()
            for t in others:
                replayed.update(per_trace[f"benign_fresh_{t}"]["alerts"])
            n_rep = sum(replayed.values())
            if 2 * replayed.get("RULE-001", 0) <= n_rep:
                raise SystemExit("the identity paragraph says most of the second phone's replay alerts come from the scan rule")
            whose = "The second phone's session" if len(others) == 1 else "The other phones' sessions"
            second = (f" {whose} on version 1.5.1, silent live, raised {word(n_rep)} when replayed without identity, "
                      f"{word(replayed['RULE-001'])} of them from the same rule.")
    n_on, n_off = sum(on["alerts"].values()), sum(off["alerts"].values())
    same_bytes = scorer.score(replay, FRESH)["benign"]["perTrace"]["benign_fresh_pixel"]
    n_replay = sum(same_bytes["alerts"].values())
    lost = sorted(s["scenario"] for s, t in zip(a["scenarios"], b["scenarios"]) if s["detected"] and not t["detected"])
    gained = sorted(s["scenario"] for s, t in zip(a["scenarios"], b["scenarios"]) if t["detected"] and not s["detected"])
    if [s["scenario"] for s in a["scenarios"]] != [s["scenario"] for s in b["scenarios"]] or gained or lost != ["tls_library_switch"]:
        raise SystemExit(f"the identity paragraph says only the TLS library scenario depends on identity: lost {lost}, gained {gained}")
    if n_on != 0 or set(off["alerts"]) != {"RULE-001"} or set(same_bytes["alerts"]) != {"RULE-001"}:
        raise SystemExit("the identity paragraph describes other alerts")
    if on["seconds"] // 60 != 13 or off["seconds"] // 60 != 13:
        raise SystemExit("the identity paragraph says both sessions ran about 13 minutes")
    v["IDENTITY_TEXT"] = (
        "We ran frozen version 1.5.0 with app identity switched off, so that detectors count per source address as a network sensor must, over two consecutive 13-minute sessions on the same sites and apps. "
        f"With identity on, the live session raised no alerts over {fmt_int(on['exportPackets'])} packets. Replaying those same packets without identity raised {word(n_replay)}, "
        f"and the live session with identity off raised {word(n_off)} over {fmt_int(off['exportPackets'])} packets, all of them the horizontal scan rule reading page loads as a scan.{second} "
        f"Of the {b['total']} attack scenarios, version 1.5.1 detected {b['detected']} with identity off, losing only the TLS library change, which needs identity by definition. "
        "These counts are small and bound the claim: on this traffic identity spares a few false alarms and changes no other detection. "
        "Beyond that, an alert with identity names the app to remove, where without it every alert names the phone's address.")
    v["ABSTRACT_IDENTITY"] = f"Switching app identity off adds {word(n_off)} false alarms in a session and stops alerts naming the app."


def optional(path):
    p = RESULTS / path
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


# Android reports model and part numbers; the paper uses the names they are sold under
SOLD_AS = {"SM-M536B": ("Galaxy M53", "mid-range "), "CPH2127": ("A53", "entry-level ")}
SOCS = {"MT": "MediaTek "}
# Qualcomm's part numbers are not the names its chips are sold under
SOC_NAMES = {"SM4250": "Snapdragon~460"}


def describe(info):
    """A phone's short name and its description, from device_info.py's record."""
    ram = min(g for g in (2, 3, 4, 6, 8, 12, 16, 24, 32) if g >= info["memTotalGiB"])
    maker = {"oppo": "Oppo"}.get(info["manufacturer"].lower(), info["manufacturer"].title())
    soc = SOC_NAMES.get(info["soc"]) or next((name + info["soc"] for prefix, name in SOCS.items() if info["soc"].startswith(prefix)), info["soc"])
    model, tier = SOLD_AS.get(info["model"], (info["marketName"] or info["model"], ""))
    name = f"{maker} {model}"
    article = "an" if (tier or maker)[0] in "AEIOUaeiou" else "a"
    return name, f"{article} {tier}{name} ({soc}, {ram}~GB RAM, Android~{info['android']})"


def devices():
    """The sentences about further phones, which go away if none was measured."""
    v = values
    phones = []
    for p in sorted(RESULTS.glob("device_*.json")):
        tag = p.stem.split("_", 1)[1]
        if tag == "pixel":
            continue
        info, live_run, session = optional(p.name), optional(f"live_attacks_{tag}.json"), optional(f"benign_live_fresh_{tag}.json")
        speed, spent = optional(f"throughput_{tag}.json"), optional(f"cost_v151_benign_smallFlows_{tag}.json")
        if not (live_run and session and speed and spent):
            continue
        name, described = describe(info)
        phones.append({"short": name, "described": described,
                       "live": live_run["detected"], "alerts": sum(session["alerts"].values()), "packets": session["exportPackets"], "speed": speed,
                       "pps": fmt_int(round(spent["stages"]["full.wall"]["bestPps"], -2))})
    if not phones:
        print("note: no further phones in this build")

    def both(field):
        return " and ".join(str(p[field]) for p in phones)

    def counted(p):
        return word(p["alerts"])

    def speed(p):
        def med(key, field):
            return st.median(p["speed"][key][field])
        rounds = len(p["speed"]["andronet_full"]["cpu"])
        return (f"The {p['short']} moved {med('andronet_full', 'down'):.0f}~Mbit/s down and {med('andronet_full', 'up'):.0f} up through the full app over {word(rounds)} rounds, "
                f"against {med('no_capture', 'down'):.0f} and {med('no_capture', 'up'):.0f} with no capture.")
    n = len(phones)
    packets = " and ".join(fmt_int(p["packets"]) for p in phones)
    v["SAMSUNG_HARDWARE"] = {0: "", 1: f"A second unrooted phone, {both('described')}, ran the live scenarios, a browsing and app session, and shorter speed tests.",
                             2: f"Two more unrooted phones, {both('described')}, each ran the live scenarios, a browsing and app session, and shorter speed tests."}[n]
    v["SAMSUNG_LIVE_TEXT"] = {0: "", 1: f"On the second phone, {both('live')} did, and its browsing and app session raised {counted(phones[0]) if n else ''} alerts over {packets} packets.",
                              2: f"On the other two phones, {both('live')} did, and their browsing and app sessions raised {' and '.join(counted(p) for p in phones)} alerts over {packets} packets."}[n]
    v["SAMSUNG_SPEED_TEXT"] = " ".join(speed(p) for p in phones)
    v["SAMSUNG_COST_TEXT"] = " ".join(f"With the scheduler free to choose its core, the {p['short']} sustains about {p['pps']}." for p in phones)
    v["DEVICES_WORD"] = {0: "one phone", 1: "two phones", 2: "three phones"}[n]
    v["LIMITS_TEXT"] = {0: "Limits were set on one phone and may not suit others", 1: "Limits were set on one phone, and a session on one other is thin evidence that they suit others",
                        2: "Limits were set on one phone, and sessions on two others are thin evidence that they suit others"}[n]


def speed_text():
    v = values
    t = need("throughput_v151final.json")
    old = need("throughput_final.json")
    if not t or not old:
        return

    def med(data, key, field):
        return st.median(data[key][field])
    full, pd, none = "andronet_full", "pcapdroid", "no_capture"
    if any(n for key in t for n in t[key].get("analysisSkipped", [])):
        raise SystemExit("the speed paragraph says the queue skipped nothing")
    ratio = min(med(t, full, "down") / med(old, full, "down"), med(t, full, "up") / med(old, full, "up"))
    if ratio <= 3:
        raise SystemExit("the speed paragraph says more than three times version 1.4.0")
    low, high = min(t[none]["down"]), max(t[none]["down"])
    if not (low <= med(t, full, "down") <= high and low <= med(t, pd, "down") <= high):
        raise SystemExit("the speed paragraph says these lie within the spread of no capture")
    if med(t, full, "cpu") <= med(t, pd, "cpu") or med(t, full, "rss") <= med(t, pd, "rss"):
        raise SystemExit("the speed paragraph says AndroNet costs more processor and memory than PCAPdroid")
    v["SPEED_TEXT"] = (
        f"The relay is no longer what limits the phone. With the full app in the background it moves {med(t, full, 'down'):.0f}~Mbit/s down and {med(t, full, 'up'):.0f} up, "
        f"over three times version 1.4.0's {med(old, full, 'down'):.0f} and {med(old, full, 'up'):.0f}, and level with PCAPdroid given the link, "
        f"since single transfers with no capture ranged from {low:.0f} to {high:.0f}~Mbit/s. The analysis queue skipped no packets in any round. "
        f"What this costs is processor and memory, {med(t, full, 'cpu'):.0f}\\% of a core and {med(t, full, 'rss'):.0f}~MiB against PCAPdroid's {med(t, pd, 'cpu'):.0f}\\% and {med(t, pd, 'rss'):.0f}~MiB, "
        "and it buys detection that PCAPdroid's free build does not run.")
    v["ABSTRACT_SPEED"] = (f"Through the full pipeline the phone moves {med(t, full, 'down'):.0f}~Mbit/s down and {med(t, full, 'up'):.0f} up, level with PCAPdroid, "
                           "and keeps quiet connections that PCAPdroid drops, at the cost of more CPU and memory.")
    v["CONCLUSION_SPEED"] = "Its relay keeps pace with PCAPdroid's and holds quiet connections that PCAPdroid drops, while using more CPU and memory."


# What the paper calls each finding a long run can report. Layer 4 goes by the identifiers of its table.
FINDING_NAMES = {
    "APP-001": "APP-001", "FLOW-001": "FLOW-001", "FLOW-002": "FLOW-002", "FLOW-003": "FLOW-003", "FLOW-004": "FLOW-004", "FLOW-005": "FLOW-005",
    "RULE-001": "the horizontal scan rule", "RULE-002": "the SQL injection rule", "RULE-003": "the executable download rule",
    "RULE-004": "the DNS tunnelling rule", "RULE-005": "the brute force rule", "RULE-006": "the cryptomining rule",
    "RULE-007": "the bulk upload rule", "RULE-008": "the shellcode rule", "RULE-009": "the scanner User-Agent rule", "RULE-010": "the ICMP tunnel rule",
    "MAL-001": "the Meterpreter signature", "MAL-002": "the WannaCry signature", "MAL-003": "the Cobalt Strike signature",
    "EXP-001": "the SQL injection signature", "EXP-002": "the directory traversal signature", "EXP-003": "the code execution signature",
    "EXP-004": "the XXE signature", "RECON-001": "the Nmap signature", "RECON-002": "the Nikto signature", "RECON-003": "the sqlmap signature",
    "C2-001": "the Tor exit list", "C2-002": "the known-C2 list", "C2-003": "the IRC bot signature", "EXFIL-001": "the Base64 exfiltration signature",
    "BRUTE-001": "the SSH login-tool signature", "BRUTE-002": "the RDP login-tool signature", "NET-001": "the EternalBlue signature", "NET-002": "the Shellshock signature",
    "PORT_SCAN": "the port scan detector", "SYN_FLOOD": "the SYN flood detector", "CONNECTION_FLOOD": "the connection flood detector",
    "DISTRIBUTED_FLOOD": "the distributed flood detector", "DNS_TUNNELING": "the DNS tunnelling detector", "ARP_SPOOFING": "the ARP spoofing detector",
    "MALFORMED_PACKET": "the malformed TCP detector", "HIGH_ENTROPY_PAYLOAD": "the covert channel detector", "COVERT_CHANNEL": "the covert channel detector",
    "UNUSUAL_TRAFFIC": "the unusual traffic detector", "ANALYSIS_OVERLOAD": "the queue overload alert",
}


def listing(parts):
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


# What Android throws at an app that keeps a data-sync foreground service running past its daily allowance
FGS_LIMIT = "ForegroundServiceDidNotStopInTimeException: A foreground service of type dataSync did not stop within its timeout"
LIMIT_TEXT = ("Android 15 and later allow a data-sync foreground service, the type version 1.5.1 declared, "
              "six hours of running time a day and crash an app that keeps one running longer.")


def soak_checks(s, tag):
    """How a long run ended: "whole" if one process held the tunnel throughout, "limit" if Android's daily limit
    on the service type ended it, "gap" for an end soak_gap can name. Refuses any result the paragraph cannot state."""
    if sum(s["byFinding"].values()) != s["alerts"] or sum(s["bySeverity"].values()) != s["alerts"]:
        raise SystemExit(f"the {tag} soak counts do not add up")
    unnamed = set(s["byFinding"]) - set(FINDING_NAMES)
    if unnamed:
        raise SystemExit(f"name these findings in FINDING_NAMES before the soak paragraph can mention them: {unnamed}")
    reports = s["crashReports"]
    if any(n is None for n in reports.values()):
        raise SystemExit(f"Android's crash reports could not be read on the {tag} phone, so the paragraph cannot say there were none")
    if s["captureStarts"] != 1:
        raise SystemExit(f"the {tag} run started capture {s['captureStarts']} times; describe its stretches by hand")
    if any(reports.values()):
        # One crash is explained here: the daily limit, ending a run that nothing else interrupted
        crashes = need(f"soak_{tag}_crashes.json") or []
        unexplained = (reports["data_app_native_crash"] or reports["data_app_anr"] or reports["data_app_crash"] != 1 or len(crashes) != 1
                       or FGS_LIMIT not in (crashes[0]["exception"] or "") or s["stillRunning"] or s["captureStops"] or s["rebootedDuringRun"])
        if unexplained:
            raise SystemExit(f"Android holds crash reports for the app on the {tag} phone ({reports}); read them before writing the soak paragraph")
        began = datetime.datetime.strptime(s["startedAt"], "%Y-%m-%d %H:%M")
        crashed = datetime.datetime.strptime(crashes[0]["timestamp"][:19], "%Y-%m-%d %H:%M:%S")
        if abs((crashed - began).total_seconds() / 3600 - s["coveredHours"]) > 0.5:
            raise SystemExit(f"the {tag} run's capture did not end at its crash; describe it by hand")
        return "limit"
    if s["stillRunning"] and not s["captureStops"] and not s["rebootedDuringRun"]:
        if abs(s["spanHours"] - s["coveredHours"]) > 0.1:
            raise SystemExit(f"the continuous {tag} run should cover its whole span")
        return "whole"
    return "gap"


def fgs_fix_text():
    """The check that version 1.5.2 outlasts the limit that ended version 1.5.1, with the limit shortened."""
    old, new = need("fgs_limit_v151.json"), need("fgs_limit_v152.json")
    if not old or not new:
        return ""
    if old["versionName"] != "1.5.1" or new["versionName"] != "1.5.2" or old["limitMinutes"] != new["limitMinutes"]:
        raise SystemExit("the limit check compared the wrong builds or limits")
    if not old["newCrashReports"] or FGS_LIMIT not in (old["exception"] or ""):
        raise SystemExit("the limit check did not reproduce the crash on version 1.5.1")
    if new["newCrashReports"] or not new["sameProcess"] or not new["tunnelUp"] or new["waitedMinutes"] <= new["limitMinutes"]:
        raise SystemExit("version 1.5.2 did not outlast the shortened limit")
    if new["limitAfterRestoreMs"] != 21_600_000 or old["limitAfterRestoreMs"] != 21_600_000:
        raise SystemExit("the phone's six-hour limit was not restored after the check")
    return (f" Version 1.5.2 declares a special-use service instead and changes nothing else; with the limit cut to {word(int(new['limitMinutes']))} minutes, "
            f"1.5.1 crashed again and 1.5.2 kept its tunnel up for all {word(round(new['waitedMinutes']))} minutes.")


def soak_gap(s, tag):
    """Why a run covered less than its span, from what the phone could say at collection."""
    if s["rebootedDuringRun"]:
        reboot = optional(f"soak_{tag}_reboot.json")
        if reboot and reboot["bootReason"].endswith(",ota") and reboot["buildAtStart"] and reboot["buildAtStart"] != reboot["buildAtCollect"]:
            return "until the phone restarted to install a system update"
        return "until the phone restarted"
    if s["captureStops"]:
        # A clean stop can be a person, another VPN app or Android's limit on the service type, and the phone keeps no record of which
        raise SystemExit("capture was stopped cleanly during a long run; find the cause and state it by hand")
    if s["process"]["processAgeHours"] is None:
        return "until the system ended the app's process"
    return "until Android replaced the app's process"


def soak_alerts(s, top, subject="It"):
    """The alert sentence of a run, naming its largest findings."""
    n, u = s["alerts"], s["unattributedAlerts"]
    if n == 0:
        return f"{subject} raised no alerts."
    found = sorted(s["byFinding"].items(), key=lambda kv: (-kv[1], kv[0]))
    shown = found if len(found) <= top + 1 else found[:top]
    parts = [f"{word(c)} from {FINDING_NAMES[k]}" for k, c in shown]
    if len(found) > len(shown):
        rest = found[len(shown):]
        parts.append(f"{word(sum(c for _, c in rest))} from {word(len(rest))} other tests")
    apps = s["appsWithAlerts"] - (1 if u else 0)
    whose = f"from {word(apps)} {'app' if apps == 1 else 'apps'}"
    if u:
        whose = f"{word(n - u)} of them {whose} and {word(u)} with no app named" if apps else "none naming an app"
    return f"{subject} raised {word(n)} {'alert' if n == 1 else 'alerts'}, about {n / s['coveredHours'] * 24:.1f} a day, {whose}: {listing(parts)}."


def pair_alerts(s, r, label):
    """One alert sentence for two runs, with findings counted across both."""
    n1, n2 = s["alerts"], r["alerts"]
    if not n1 and not n2:
        return "Neither phone raised an alert."
    pixel = f"{word(n1)} {'alert' if n1 == 1 else 'alerts'}, about {n1 / s['coveredHours'] * 24:.1f} a day" if n1 else "no alerts"
    other = f"{word(n2)}, about {n2 / r['coveredHours'] * 24:.1f} a day" if n2 else "none"
    u, n = s["unattributedAlerts"] + r["unattributedAlerts"], n1 + n2
    named = "each naming an app" if not u else "none naming an app" if u == n else f"all but {word(u)} naming an app"
    found = sorted((collections.Counter(s["byFinding"]) + collections.Counter(r["byFinding"])).items(), key=lambda kv: (-kv[1], kv[0]))
    shown = found if len(found) <= 4 else found[:3]
    # Words below ten and digits from ten, so one list never mixes "16" with "twelve"
    def count(c):
        return word(c) if c < 10 else str(c)
    parts = [f"{count(c)} from {FINDING_NAMES[k]}" for k, c in shown]
    if len(found) > len(shown):
        parts.append(f"{count(sum(c for _, c in found[3:]))} from {word(len(found) - 3)} other tests")
    return f"The Pixel raised {pixel}, and the {label} {other}, {named}: {listing(parts)}."


def soak_text():
    """The long runs in everyday use, from counts only: the Pixel's, then any other phone soak.py recorded
    starting. A recorded start makes its result a gap until collected, so a run is reported whatever it shows."""
    v = values
    s = need("soak_pixel.json")
    others = []
    for p in sorted(RESULTS.glob("soak_*_start.json")):
        tag = p.name[len("soak_"):-len("_start.json")]
        if tag != "pixel":
            run_result, info = need(f"soak_{tag}.json"), need(f"device_{tag}.json")
            if run_result and info:
                others.append((tag, run_result, info))
    if not s:
        return
    if len(others) > 1:
        raise SystemExit("the soak paragraph is written for at most two phones")
    ending = soak_checks(s, "pixel")
    continuous = ending == "whole"
    span, covered, n = s["spanHours"], s["coveredHours"], s["alerts"]
    proc = s["process"]
    v["SOAK_PHONES_NOTE"] = ""
    limited = []

    def outcome(name, x, how, tag):
        """What happened to one phone's capture, as a sentence."""
        if how == "whole":
            return f"The {name} held its tunnel in one process for all {x['spanHours']:.0f} hours, with no crash or freeze recorded."
        if how == "limit":
            limited.append(tag)
            runtime = need(f"soak_{tag}_crashes.json")[0]["processRuntimeHours"]
            return f"On the {name}, capture ended after {x['coveredHours']:.0f} hours, once the app had run for {word(round(runtime))}: {LIMIT_TEXT}"
        return f"On the {name}, capture ran for {x['coveredHours']:.0f} hours in one process, {soak_gap(x, tag)}, with no crash or freeze recorded."

    if not others:
        text = [f"The Pixel~8, an author's own phone, ran version 1.5.1 in everyday use, logging only each alert's time, finding and app, "
                "with profiles empty at the start so that learning the phone's apps counted against the result.",
                outcome("Pixel", s, ending, "pixel")]
        if limited:
            text[-1] += fgs_fix_text()
        if continuous:
            text.append(f"It analysed {s['packets'] / 1e6:.1f}~million packets, the queue skipped {fmt_int(s['skippedPackets']) if s['skippedPackets'] else 'none'}, "
                        f"its process averaged {proc['avgCpuPct']:.1f}\\% of a core over the run, and its memory peaked at {proc['peakRssMiB']}~MiB.")
        else:
            text.append(f"It analysed {s['packets'] / 1e6:.1f}~million packets, and the queue skipped {fmt_int(s['skippedPackets']) if s['skippedPackets'] else 'none'}.")
        text.append(soak_alerts(s, 3))
        total_h, total_n = covered, n
    else:
        # Two phones share each sentence, which a page limit needs
        tag, r, info = others[0]
        other_ending = soak_checks(r, tag)
        steady = other_ending == "whole"
        _, described = describe(info)
        label = describe(info)[0].split()[0]
        text = [f"Two phones ran version 1.5.1 in their owners' everyday use, with profiles empty at the start and logging only each alert's time, finding and app: "
                f"the Pixel~8, an author's own phone, and {described}."]
        if continuous and steady:
            text.append(f"On both, one process held the tunnel throughout, for {span:.0f} and {r['spanHours']:.0f} hours, and Android recorded no crash or freeze of the app.")
        else:
            for name, x, how, t in (("Pixel", s, ending, "pixel"), (label, r, other_ending, tag)):
                text.append(outcome(name, x, how, t))
                # The fix follows the first run the limit ended
                if how == "limit" and len(limited) == 1:
                    text[-1] += fgs_fix_text()
            if len(limited) == 2:
                raise SystemExit("both runs ended at the limit; write the soak paragraph by hand")
        skips = (s["skippedPackets"], r["skippedPackets"])
        skipped = "none" if not any(skips) else f"{fmt_int(skips[0])} and {fmt_int(skips[1])} packets"
        load = f"They analysed {s['packets'] / 1e6:.1f} and {r['packets'] / 1e6:.1f}~million packets"
        whole = [(name, x["process"]) for name, x, ok in (("Pixel", s, continuous), (label, r, steady)) if ok]
        if len(whole) == 2:
            text.append(f"{load}, the queue skipped {skipped}, and the process averaged {whole[0][1]['avgCpuPct']:.1f} and {whole[1][1]['avgCpuPct']:.1f}\\% of a core, "
                        f"with memory peaking at {whole[0][1]['peakRssMiB']} and {whole[1][1]['peakRssMiB']}~MiB.")
        elif whole:
            text.append(f"{load} with {skipped} skipped, and the {whole[0][0]}'s process averaged {whole[0][1]['avgCpuPct']:.1f}\\% of a core "
                        f"and peaked at {whole[0][1]['peakRssMiB']}~MiB.")
        else:
            text.append(f"{load} with {skipped} skipped.")
        text.append(pair_alerts(s, r, label))
        for name, x in (("Pixel", s), (label, r)):
            if x["alerts"] and not x["unattributedAlerts"]:
                f, count = max(x["byFinding"].items(), key=lambda kv: kv[1])
                gap = x.get("topAppRepeatHours", {}).get(f)
                if count >= 5 and x["alertsPerApp"].get(f) == [count] and gap:
                    cadence = ("about once an hour" if 0.75 <= gap <= 1.5 else f"about every {gap:.0f} hours" if gap > 1.5
                               else f"about every {gap * 60:.0f} minutes")
                    text.append(f"The {name}'s {word(count)} {FINDING_NAMES[f]} alerts all came from one app, {cadence}.")
        total_h, total_n = covered + r["coveredHours"], n + r["alerts"]
        v["SOAK_PHONES_NOTE"] = f" on the Pixel 8 and {described.split(' (')[0]}"
    if total_n:
        text.append("No attack was staged, so we count every alert as a false alarm.")
    v["SOAK_TEXT"] = " ".join(text)
    v["SOAK_HOURS"] = f"{total_h:.0f}"
    v["ABSTRACT_SOAK"] = (f"In {total_h:.0f} hours of everyday use{' on two phones' if others else ''} it raised "
                          f"{word(total_n) if total_n else 'no'} {'alert' if total_n == 1 else 'alerts'}"
                          + (" and hit Android~15's six-hour daily cap on capture, now fixed." if limited else "."))


def energy_text():
    """Whole-device power under load and at idle, against no capture and PCAPdroid."""
    v = values
    e = need("energy_summary.json")
    if not e:
        return
    conds = ("none", "pcapdroid", "andronet")
    w = e["work"]
    for work in ("traffic", "idle"):
        for c in conds:
            x = w[work][c]
            if x["meanW"] <= 0 or x["runs"] < 2:
                raise SystemExit(f"energy: {work} {c} has {x['runs']} usable runs at {x['meanW']:.2f} W")
    with open(RESULTS / "energy_runs.csv") as f:
        for row in csv.DictReader(f):
            if (row["cond"] == "none") != (row["tun"] == "0"):
                raise SystemExit(f"energy run {row['cond']} {row['work']} {row['rep']} had {row['tun']} tunnels")
    t, i = w["traffic"], w["idle"]

    def extra(base, c):
        return base[c]["meanW"] - base["none"]["meanW"]
    spread_t = max(x["stdevW"] for x in t.values())
    spread_i = max(x["stdevW"] for x in i.values())
    if extra(t, "andronet") <= spread_t and extra(t, "pcapdroid") <= spread_t:
        load = "Under the 10~Mbit/s download both apps' draw stays within the spread between repetitions of the no-capture baseline"
    else:
        def loaded(c, name):
            return f"{name} adds {extra(t, c):.2f}~W to the no-capture baseline" if extra(t, c) > spread_t else f"{name}'s draw stays within the spread between repetitions"
        load = f"Under the 10~Mbit/s download {loaded('andronet', 'AndroNet')}, while {loaded('pcapdroid', 'PCAPdroid')}"
    load += f", with AndroNet's process at {t['andronet']['cpuPct']:.0f}\\% of a core against PCAPdroid's {t['pcapdroid']['cpuPct']:.0f}\\%."
    if max(x["meanW"] for x in i.values()) - min(x["meanW"] for x in i.values()) <= spread_i:
        quiet = "At idle the three differ by less than the spread between repetitions."
    else:
        # An addition is stated only where it exceeds the spread, as under load
        def idle(c, name):
            return f"{name} adds {extra(i, c):.2f}~W" if extra(i, c) > spread_i else f"{name}'s draw stays within the spread"
        quiet = f"At idle {idle('andronet', 'AndroNet')}, while {idle('pcapdroid', 'PCAPdroid')}."
    dropped = len(e["excludedRuns"])
    if dropped:
        quiet += f" {word(dropped).capitalize()} {'run' if dropped == 1 else 'runs'} in which the cable was reconnected early {'is' if dropped == 1 else 'are'} excluded."
    v["ENERGY_TEXT"] = f"{load} {quiet}"
    v["EN_REPS"] = word(min(w[work][c]["runs"] for work in ("traffic", "idle") for c in conds))


def abstract_words(text):
    body = text[text.index(r"\begin{abstract}") + len(r"\begin{abstract}"):text.index(r"\keywords")]
    body = re.sub(r"\\[a-zA-Z]+", " ", body.replace("~", " ").replace("{,}", ","))
    return len([t for t in body.split() if re.search(r"[A-Za-z0-9]", t)])


def misses():
    m = need("miss_analysis.json")
    if not m:
        return
    v = values
    v["MISS_ICMP_SRCS"] = fmt_int(m["icmpFlood"]["distinctSources"])
    v["MISS_NMAP_PORTS"] = word(len(m["nmapVersion"]["ports"]))


def live():
    v = values
    a = need("live_attacks_v151final.json")
    r = need("rooted_v151final.json")
    if a:
        v["LIVE_TOTAL"], v["LIVE_DETECTED"] = str(a["total"]), str(a["detected"])
        if "tls_library_switch" not in {s["scenario"] for s in a["scenarios"] if s["detected"]}:
            raise SystemExit("the live paragraph says a TLS library change was detected")
    if a and r:
        shared = {s["scenario"]: s for s in r["scenarios"] if s["scenario"] in {x["scenario"] for x in a["scenarios"]}}
        same = sum(1 for s in a["scenarios"] if s["scenario"] in shared and s["detected"] == shared[s["scenario"]]["detected"])
        v["SHARED_SCENARIOS"] = str(len(shared))
        v["PARITY_WORD"] = "the same" if same == len(shared) else f"the same (on {same} of {len(shared)})"
        if {s["scenario"] for s in a["scenarios"]} - set(shared) != {"tls_library_switch"}:
            raise SystemExit("the parity paragraph says one scenario was left out")
        v["INJECTED_N"] = str(r["total"] - len(shared))
        v["HELPER_EXIT"] = "5"  # rooted_experiment.py counts helpers 5 s after the force-stop
        if str(r.get("helpersLeftAfterStop")) != "0":
            raise SystemExit("helper survived the stop in the rooted run")
    ann = need("annotation_check.json")
    if ann:
        if not ann["frameCommentPackets"] or ann["frameCommentPackets"] != ann["annotationStringsInFile"]:
            raise SystemExit("exported annotations are not all visible to tshark")
        v["EXPORT_PKTS"] = fmt_int(int(ann["capinfos"].rsplit(",", 1)[-1].strip('"')))
    vis = need("visibility.json")
    if vis:
        scans = [k for k in vis if isinstance(vis[k], dict)]
        v["VIS_SCANS"] = word(len(scans))
        v["VIS_ANSWERED"] = fmt_int(sum(vis[k]["portsAnswered"] for k in scans))
        v["VIS_ALERTS"] = word(vis["scanAlerts"])
    u = need("unit_tests.json")
    if u:
        if u["failures"] or u["errors"]:
            raise SystemExit("unit tests failing")
        v["UNIT_TESTS"] = str(u["tests"])
    fp = need("fingerprint_check.json")
    if fp:
        if fp["compared"] != fp["ja3Match"] or fp["compared"] != fp["ja4Match"]:
            raise SystemExit("fingerprints no longer match Wireshark's on every hello")
        v["FP_COMPARED"] = fmt_int(fp["compared"])
    variety = need("fingerprint_variety.json")
    if variety:
        v["FPV_JA4"] = str(variety["benign_phone_dev3"]["distinctJa4"])
        v["FPV_LISTS"] = str(variety["benign_phone_dev3"]["distinctCipherLists"])


def cost():
    v = values
    b = need("cost_baseline_benign_smallFlows_mid.json")
    c = need("cost_v151_benign_smallFlows_v151mid.json")
    big = need("cost_v151_benign_smallFlows_v151big.json")
    little = need("cost_v151_benign_smallFlows_v151little.json")

    def parts(r):
        s = r["stages"]
        l1 = s["noRulesNoSigs.detect"]["meanUs"]
        l2 = s["noRules.detect"]["meanUs"] - l1
        l3 = s["full.detect"]["meanUs"] - s["noRules.detect"]["meanUs"]
        return s, l1, l2, l3

    if b:
        s, _, _, l3 = parts(b)
        v["B_MEAN_MS"] = f"{s['full.total']['meanUs'] / 1000:.1f}"
        v["B_PPS"] = f"{s['full.wall']['bestPps']:.0f}"
        v["B_L3_MS"] = f"{l3 / 1000:.1f}"
        v["B_DPI_US"] = f"{s['full.dpi']['meanUs']:.0f}"
    if c:
        s, _, _, l3 = parts(c)
        v["V_MEAN_US"] = f"{s['full.total']['meanUs']:.0f}"
        v["V_P50_US"] = f"{s['full.total']['p50Us']:.0f}"
        v["V_P95_US"] = f"{s['full.total']['p95Us']:.0f}"
        v["V_L3_US"] = f"{l3:.0f}"
        v["V_DPI_US"] = f"{s['full.dpi']['meanUs']:.0f}"
        v["V_PPS"] = fmt_int(round(s["full.wall"]["bestPps"], -2))
        v["V_HEAP_KIB"] = fmt_int(c["heap"]["deltaBytes"] / 1024)
    if big:
        v["V_BIG_PPS"] = fmt_int(round(big["stages"]["full.wall"]["bestPps"], -2))
    if little:
        v["V_LITTLE_PPS"] = fmt_int(round(little["stages"]["full.wall"]["bestPps"], -2))
    wild = need("cost_baseline_nowild_benign_smallFlows_mid.json")
    if wild:
        v["W_L3_US"] = f"{parts(wild)[3]:.0f}"
    hexless = need("cost_baseline_nohex_benign_smallFlows_mid.json")
    if hexless:
        v["H_DPI_US"] = f"{hexless['stages']['full.dpi']['meanUs']:.0f}"


def head_to_head():
    v = values
    t = need("throughput_v151final.json")
    old = need("throughput_final.json")

    def med(data, key, field, digits=0):
        points = data[key][field]
        return f"{st.median(points):.{digits}f}" if points else "--"

    def fill(tag, data, key):
        v[f"TP_{tag}_D"] = med(data, key, "down")
        v[f"TP_{tag}_U"] = med(data, key, "up")
        v[f"TP_{tag}_R"] = med(data, key, "rttP50", 1)
        v[f"TP_{tag}_C"] = med(data, key, "cpu")
        v[f"TP_{tag}_M"] = med(data, key, "rss")

    if old:
        fill("OLD", old, "andronet_full")
    if t:
        rounds = need("throughput_v151final_meta.json")
        v["TP_ROUNDS"] = word(rounds["rounds"]) if rounds else "several"
        for tag, key in (("NONE", "no_capture"), ("PD", "pcapdroid"), ("ANF", "andronet_forward"), ("ANG", "andronet_foreground"), ("AN", "andronet_full")):
            fill(tag, t, key)
    e = need("energy_summary.json")
    e_old = need("v140/energy_summary.json")
    if e:
        w = e["work"]
        for tag, key in (("NONE", "none"), ("PD", "pcapdroid"), ("AN", "andronet")):
            tr, idle = w["traffic"][key], w["idle"][key]
            v[f"EN_T_{tag}"] = f"{tr['meanW']:.2f}"
            v[f"EN_I_{tag}"] = f"{idle['meanW']:.2f}"
            v[f"EN_TP_{tag}"] = f"{tr['pctPerHour']:.1f}"
            v[f"EN_IP_{tag}"] = f"{idle['pctPerHour']:.1f}"
    if e_old:
        w = e_old["work"]
        tr, idle = w["traffic"]["andronet"], w["idle"]["andronet"]
        v["EN_T_OLD"] = f"{tr['meanW']:.2f}"
        v["EN_I_OLD"] = f"{idle['meanW']:.2f}"
        v["EN_TP_OLD"] = f"{tr['pctPerHour']:.1f}"
        v["EN_IP_OLD"] = f"{idle['pctPerHour']:.1f}"
    v["B_THROUGHPUT"] = "15"  # measured 14.5 and 15.4 Mbit/s before the single-loop fix; see evaluation/README.md


def predicates():
    source = (HERE.parent / "android/app/src/main/kotlin/com/example/packet_analyzer/RuleEngine.kt").read_text(encoding="utf-8")
    block = source[source.index("sealed class Condition"):]
    block = block[:block.index("\n    }\n")] if "\n    }\n" in block else block
    kinds = re.findall(r"^\s+(?:data class|class|object) (\w+)", block, flags=re.M)
    values["PREDICATES"] = str(len([k for k in kinds if k not in ("And", "Or", "Not")]))


def fill(template, draft):
    def sub(m):
        key = m.group(1)
        if key in values:
            return values[key]
        missing.append(key)
        return r"\textbf{[" + key.replace("_", r"\_") + "]}"
    text = re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, template)
    authors = (HERE / "authors.tex").read_text(encoding="utf-8")
    text = text.replace("<<AUTHOR_BLOCK>>", authors)
    ack_path = HERE / "acknowledgments.txt"
    ack = ack_path.read_text(encoding="utf-8").strip() if ack_path.exists() else ""
    text = text.replace("<<ACKNOWLEDGMENTS>>", ack)
    return text, ("PLACEHOLDER" in authors)


def run(cmd, cwd=HERE):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")


def latex(name):
    r = run([str(TEX / "pdflatex.exe"), "-interaction=nonstopmode", f"{name}.tex"])
    return r.stdout


def compile_all():
    # The class and style come straight from the template the organisers named
    for f in ("llncs.cls", "splncs04.bst"):
        if not (HERE / f).exists():
            raise SystemExit(f"{f} missing; copy it from Springer's LaTeX2e Proceedings Template")
    if (HERE / "fig_architecture.tex").stat().st_mtime > ((HERE / "fig_architecture.pdf").stat().st_mtime if (HERE / "fig_architecture.pdf").exists() else 0):
        r = run([str(TEX / "pdflatex.exe"), "-interaction=nonstopmode", "fig_architecture.tex"])
        if "Output written" not in r.stdout:
            print(r.stdout[-1500:])
            raise SystemExit("figure failed")
    latex("andronet")
    run([str(TEX / "bibtex.exe"), "andronet"])
    latex("andronet")
    log = latex("andronet")
    for line in log.splitlines():
        if line.startswith("!") or "Overfull \\hbox" in line or "undefined" in line.lower() or "Output written" in line:
            print(line[:140])
    return log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", action="store_true")
    args = ap.parse_args()
    global FINAL
    FINAL = args.final

    first_cycle()
    second_cycle()
    yardstick()
    live_text()
    idle_text()
    identity_text()
    speed_text()
    devices()
    misses()
    live()
    cost()
    head_to_head()
    energy_text()
    soak_text()
    predicates()

    if "F_T" in values and "F15_D" in values:
        values["F_T_MISSED"] = str(int(values["F_T"]) - int(values["F15_D"]))
        values["F_RAT_MISSED"] = str(int(values["F_RAT_T"]) - int(values["F15_RAT_D"]))
    values["SECOND_PHONE_NOTE"] = {"two phones": " and a second phone", "three phones": " and two more phones"}.get(values.get("DEVICES_WORD"), "")
    note = (HERE / "reviewer_response.template.md").read_text(encoding="utf-8")
    (HERE / "reviewer_response.md").write_text(re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: values.get(m.group(1), m.group(0)), note), encoding="utf-8")
    text, placeholder_authors = fill(TEMPLATE.read_text(encoding="utf-8"), not args.final)
    # Springer asks for an abstract of 150 to 250 words
    words = abstract_words(text)
    print("abstract words:", words)
    if args.final and not 150 <= words <= 250:
        raise SystemExit(f"the abstract has {words} words; Springer asks for 150 to 250")
    OUT.write_text(text, encoding="utf-8")
    (RESULTS / "paper_values.json").write_text(json.dumps(values, indent=1))
    log = compile_all()
    pages = re.search(r"Output written on andronet\.pdf \((\d+) pages?", log)

    gaps = sorted(set(missing))
    print("gaps:", gaps if gaps else "none")
    print("author placeholders:", placeholder_authors)
    if args.final:
        if gaps or placeholder_authors:
            raise SystemExit("not final: gaps or author placeholders remain")
        # The call allows 10 to 15 pages, everything included
        if not pages or not 10 <= int(pages.group(1)) <= 15:
            raise SystemExit(f"not final: the paper has {pages.group(1) if pages else 'an unknown number of'} pages; the limit is 15")
        if "Overfull \\hbox" in log:
            raise SystemExit("not final: a line runs into the margin")
        bundle = HERE / "andronet_source.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
            for name in ZIP_FILES:
                z.write(HERE / name, name)
        shutil.copy(HERE / "andronet.pdf", HERE / "andronet_final.pdf")
        print("wrote", bundle)


if __name__ == "__main__":
    main()
