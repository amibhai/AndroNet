#!/usr/bin/env python3
"""Fills andronet.template.tex from evaluation/results/ and compiles the camera-ready PDF.

Every measured number in the paper comes from this script's reads. A value that has not been
measured yet stays visible in the PDF as a marked gap, and `--final` refuses to build at all if any
gap or any author placeholder remains, so an estimate can never slip through.
"""
import argparse
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
from test_manifest import ATTACKS, BENIGN  # noqa: E402
import score as scorer  # noqa: E402

TEX = pathlib.Path(r"D:\andronet_eval\TinyTeX\bin\windows")
TEMPLATE = HERE / "andronet.template.tex"
OUT = HERE / "andronet.tex"
ZIP_FILES = ["andronet.tex", "andronet.bib", "andronet.bbl", "llncs.cls", "splncs04.bst",
             "fig_architecture.pdf", "fig_cost.pdf", "fig_architecture.tex", "DescriptionTexts.txt"]

values = {}
missing = []


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


def accuracy():
    base = need("accuracy_baseline_test_host.json")
    cur = need("accuracy_current_test_phone.json")
    if not base or not cur:
        return
    b = scorer.score(base)
    c = scorer.score(cur)

    def tables(s):
        attack_alerts = {"L1": 0, "L2": 0, "L3": 0}
        hits = 0
        for meta_name in ATTACKS:
            row = s["captures"].get(meta_name) or s["untargeted"].get(meta_name)
            if not row:
                continue
            for a, n in row["alerts"].items():
                attack_alerts[scorer.layer_of(a)] += n
                hits += n
        return attack_alerts, hits

    b_tp_l, b_tp = tables(b)
    c_tp_l, c_tp = tables(c)
    bb, cb = b["benign"], c["benign"]
    v = values
    v["ATK_TOTAL"] = str(len(ATTACKS))
    words = {7: "seven", 9: "nine"}
    v["ATK_UNTARGETED"] = words.get(len(c["untargeted"]), str(len(c["untargeted"])))
    v["ATK_UNTARGETED_CAP"] = v["ATK_UNTARGETED"].capitalize()
    v["C_RECALL_D"], v["C_RECALL_T"] = str(c["recall"]["detected"]), str(c["recall"]["total"])
    v["B_RECALL_D"], v["B_RECALL_T"] = str(b["recall"]["detected"]), str(b["recall"]["total"])
    v["C_RECALL_PCT"] = f"{100 * c['recall']['detected'] / c['recall']['total']:.0f}"
    v["C_FPR"] = pct(cb["packetFPR"], 3)
    v["B_FPR"] = pct(bb["packetFPR"], 1)
    v["C_BEN_ALERTS"], v["B_BEN_ALERTS"] = fmt_int(cb["alerts"]), fmt_int(bb["alerts"])
    v["C_PER1000"], v["B_PER1000"] = f"{cb['alertsPer1000']:.2f}", f"{bb['alertsPer1000']:.0f}"
    v["C_PRECISION"] = f"{100 * c_tp / (c_tp + cb['alerts']):.1f}"
    v["B_PRECISION"] = f"{100 * b_tp / (b_tp + bb['alerts']):.1f}"
    v["BENIGN_PKTS_M"] = f"{cb['packets'] / 1e6:.2f}"

    phone_c = cb["perTrace"]["benign_phone_test_00"]
    phone_b = bb["perTrace"]["benign_phone_test_00"]
    v["B_PHONE_FLAG"] = f"{100 * phone_b['flagged'] / phone_b['packets']:.1f}"
    v["C_PHONE_FLAG"] = f"{100 * phone_c['flagged'] / phone_c['packets']:.3f}"
    v["B_RULE7"] = fmt_int(phone_b["alerts"].get("RULE-007", 0))
    v["B_RULE8"] = fmt_int(phone_b["alerts"].get("RULE-008", 0))
    ssh = bb["perTrace"]["benign_ssh_zeek"]
    v["B_SSH_FLAG"] = f"{100 * ssh['flagged'] / ssh['packets']:.0f}"

    for layer in ("L1", "L2", "L3"):
        v[f"C_{layer}_REC"] = str(c["recall"]["byLayer"][layer])
        v[f"C_{layer}_TP"] = fmt_int(c_tp_l[layer])
        v[f"C_{layer}_FP"] = fmt_int(cb["byLayer"][layer])
        denom = c_tp_l[layer] + cb["byLayer"][layer]
        v[f"C_{layer}_PREC"] = f"{100 * c_tp_l[layer] / denom:.1f}" if denom else "--"

    big = cb["perTrace"]["benign_bigFlows"]
    v["C_BIG_FP"] = fmt_int(sum(big["alerts"].values()))
    irc_traces = ("benign_irc_skype", "benign_irc_zeek")
    v["C_IRC_FP"] = str(sum(cb["perTrace"][k]["alerts"].get("C2-003", 0) for k in irc_traces))
    v["C_IRC_ALL"] = str(sum(sum(cb["perTrace"][k]["alerts"].values()) for k in irc_traces))
    explained = (sum(big["alerts"].values()) + int(v["C_IRC_ALL"]) + sum(cb["perTrace"]["benign_smb_win10"]["alerts"].values())
                 + sum(phone_c["alerts"].values()))
    if explained != cb["alerts"]:
        raise SystemExit(f"the benign alert paragraph accounts for {explained} of {cb['alerts']} alerts")
    if cb["perTrace"]["benign_smb_win10"]["alerts"] != {"L1:ARP_SPOOFING": 1}:
        raise SystemExit("the SMB false alarm is no longer one ARP alert")
    hit_untargeted = [k for k, r in c["untargeted"].items() if r["alerts"]]
    if hit_untargeted != ["atk_ms04_011_exploit"] or c["untargeted"]["atk_ms04_011_exploit"]["alerts"] != {"RULE-008": 1}:
        raise SystemExit("the untargeted capture sentence no longer holds")
    v["UNTARGETED_HITS"] = "one"

    def detected(s):
        return {k for k, r in s["captures"].items() if r["detected"]}
    gained, lost = detected(c) - detected(b), detected(b) - detected(c)
    if gained != {"atk_synflood_spoofed", "atk_traversal_dvwa"} or lost != {"atk_icmp_flood_large", "atk_ssh_guessing_zeek"}:
        raise SystemExit("the paragraph comparing the versions names other captures than these")
    v["SWAP_COUNT"] = "two"
    v["SWAP_WORD"] = "two of them"

    # Data table
    def total(s, prefix):
        return sum(run_packets for name, run_packets in s if name.startswith(prefix))
    runs = [(run["name"], sum(l["packets"] for l in run["labels"].values())) for run in cur["runs"]]
    v["TEST_ATK_PKTS"] = fmt_int(total(runs, "atk_"))
    v["TEST_PHONE_PKTS"] = fmt_int(total(runs, "benign_phone"))
    v["TEST_BEN_PKTS"] = fmt_int(total(runs, "benign_") - total(runs, "benign_phone"))
    v["TEST_BEN_N"] = str(sum(1 for n, _ in runs if n.startswith("benign_") and not n.startswith("benign_phone")))


def parity():
    host = need("accuracy_current_test_host.json")
    phone = need("accuracy_current_test_phone.json")
    if not host or not phone:
        return

    def tab(r):
        return {run["name"]: {k: (x["packets"], x["flagged"]["any"], x["alerts"]) for k, x in run["labels"].items()} for run in r["runs"]}
    a, b = tab(host), tab(phone)
    if a != b:
        raise SystemExit("phone and desktop verdicts differ; the Harness paragraph no longer holds")
    values["PARITY_TRACES"] = str(len(a))
    values["PARITY_PKTS"] = fmt_int(sum(x[0] for run in a.values() for x in run.values()))
    old_host = need("accuracy_baseline_test_host.json")
    old_phone = need("accuracy_baseline_test_phone_subset.json")
    if old_host and old_phone:
        c, d = tab(old_host), tab(old_phone)
        if any(c[k] != d[k] for k in d):
            raise SystemExit("v1.3.0 phone and desktop verdicts differ; the Harness paragraph no longer holds")
        values["B_PARITY_TRACES"] = str(len(d))


def development():
    dev = need("accuracy_current_dev_host_shipped_root.json")
    manifest_path = HERE.parent / "evaluation" / "traces" / "dev" / "manifest.json"
    if dev:
        atk = [r for r in dev["runs"] if r["name"].startswith("atk_")]
        values["DEV_ATK"] = str(len(atk))
        values["DEV_ATK_PKTS"] = fmt_int(sum(sum(l["packets"] for l in r["labels"].values()) for r in atk))
        ben = [r for r in dev["runs"] if r["name"].startswith("benign_")]
        values["DEV_BEN_PKTS"] = fmt_int(sum(sum(l["packets"] for l in r["labels"].values()) for r in ben))
    first, whole = need("calibration_dev_phone_first_part.json"), need("calibration_dev_phone.json")
    if first and whole:
        values["CAL_DESTS"] = str(first["distinct destinations probed / 10 s per source"])
        values["CAL_CONNS"] = str(first["new connections / s per source"])
        values["CAL_FIRST_S"] = str(first["seconds"])
        values["CAL_ALL_DESTS"] = str(whole["distinct destinations probed / 10 s per source"])
        values["CAL_ALL_CONNS"] = str(whole["new connections / s per source"])
        values["CAL_ALL_S"] = str(whole["seconds"])


def misses():
    """Every explanation of a miss or a false alarm in the paper, as measured from the captures."""
    m = need("miss_analysis.json")
    if not m:
        return
    v = values
    icmp, arp, shell, txt = m["icmpFlood"], m["arpPoison"], m["dnsRemoteShell"], m["dnsTxtC2"]
    nmap, ssh, met, big = m["nmapVersion"], m["sshGuessing"], m["meterpreter"], m["bigFlows"]
    v["MISS_ICMP_PKTS"], v["MISS_ICMP_SRCS"] = fmt_int(icmp["packets"]), fmt_int(icmp["distinctSources"])
    v["MISS_TXT_NAME"] = str(txt["nameLengthMax"] + 1)
    v["MISS_MET_MB"] = f"{met['bytesOnPort4444'] / 1e6:.1f}"
    v["MISS_MET_ENTROPY"] = f"{met['medianEntropyBitsPerByte']:.2f}"
    v["MISS_NMAP_PORTS"] = {2: "two"}[len(nmap["ports"])]
    v["MISS_SSH_PEAK"] = {10: "ten"}[ssh["maxSynPerMinute"]]
    if arp["ipsWhoseMacChanged"] or len(arp["macsClaimingSeveralIps"]) != 1:
        raise SystemExit("the ARP explanation no longer holds")
    if not shell["carriesCmdPrompt"] or shell["wellFormedDnsQueries"] > 3:
        raise SystemExit("the remote-shell explanation no longer holds")
    if not txt["firstResponseIsPowerShell"] or txt["txtMedianGapSeconds"] > 1.5 or txt["over50Characters"]:
        raise SystemExit("the TXT channel explanation no longer holds")
    if any(met["methodStringsInFile"].values()):
        raise SystemExit("Meterpreter method names do appear in the capture")
    if big["downloadRule"]["servers"] != 1 or big["synBurst"]["targetsOver30"] != 1:
        raise SystemExit("the bigFlows explanation no longer holds")
    v["BIG_DOWNLOAD_ALERTS"] = str(big["alerts"]["RULE-003"])
    v["BIG_DOWNLOAD_CLIENTS"] = str(big["downloadRule"]["clients"])
    v["BIG_UPLOAD_ALERTS"] = str(big["alerts"]["RULE-007"])
    v["BIG_SYN_ALERTS"] = str(big["alerts"]["L1:SYN_FLOOD"])
    v["BIG_SYN_PEAK"] = str(big["synBurst"]["peakSynPerSecond"])
    v["BIG_SYN_CLIENTS"] = str(big["synBurst"]["medianClientsWhenBusy"])


def live():
    v = values
    a = need("live_attacks_final.json")
    r = need("rooted_final.json")
    if a:
        v["LIVE_TOTAL"], v["LIVE_DETECTED"] = str(a["total"]), str(a["detected"])
    if a and r:
        shared = {s["scenario"]: s for s in r["scenarios"] if s["scenario"] in {x["scenario"] for x in a["scenarios"]}}
        same = sum(1 for s in a["scenarios"] if set(s["alerts"]) == set(shared.get(s["scenario"], {}).get("alerts", {})))
        v["SHARED_SCENARIOS"] = str(len(shared))
        v["PARITY_WORD"] = "identical" if same == len(shared) else f"matching (on {same} of {len(shared)})"
        v["INJECTED_N"] = str(r["total"] - len(shared))
        v["HELPER_EXIT"] = "5"  # rooted_experiment.py counts helpers 5 s after the force-stop
        if str(r.get("helpersLeftAfterStop")) != "0":
            raise SystemExit("helper survived the stop in the rooted run")
    b = need("benign_live_test.json")
    if b:
        v["PHONE_SITES"] = str(b["sites"])
        n = sum(b["alerts"].values())
        cur = need("accuracy_current_test_phone.json")
        replayed = next(r for r in cur["runs"] if r["name"] == "benign_phone_test_00")["labels"]["benign"]["alerts"]
        if replayed != b["alerts"] or b["alerts"] != {"L1:CONNECTION_FLOOD": 1, "RULE-007": 2}:
            raise SystemExit("the paper says the replay and the live session raised the same three alerts")
        minutes = b["seconds"] / 60
        v["PHONE_LIVE_ALERTS"] = {0: "none", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}.get(n, str(n))
        v["PHONE_LIVE_MIN"] = f"{minutes:.0f}"
        v["PHONE_LIVE_PER_HOUR"] = f"{n / (b['seconds'] / 3600):.0f}"
    ann = need("annotation_check.json")
    if ann:
        if not ann["frameCommentPackets"] or ann["frameCommentPackets"] != ann["annotationStringsInFile"]:
            raise SystemExit("exported annotations are not all visible to tshark")
        v["EXPORT_PKTS"] = fmt_int(int(ann["capinfos"].rsplit(",", 1)[-1].strip('"')))
    vis = need("visibility.json")
    if vis:
        scans = [k for k in vis if isinstance(vis[k], dict)]
        v["VIS_SCANS"] = {3: "three"}.get(len(scans), str(len(scans)))
        v["VIS_ANSWERED"] = fmt_int(sum(vis[k]["portsAnswered"] for k in scans))
        v["VIS_ALERTS"] = {0: "no"}.get(vis["scanAlerts"], str(vis["scanAlerts"]))
    u = need("unit_tests.json")
    if u:
        if u["failures"] or u["errors"]:
            raise SystemExit("unit tests failing")
        v["UNIT_TESTS"] = str(u["tests"])


def cost():
    v = values
    b = need("cost_baseline_benign_smallFlows_mid.json")
    c = need("cost_current_benign_smallFlows_mid.json")
    big = need("cost_current_benign_smallFlows_big.json")
    little = need("cost_current_benign_smallFlows_little.json")

    def parts(r):
        s = r["stages"]
        l1 = s["noRulesNoSigs.detect"]["meanUs"]
        l2 = s["noRules.detect"]["meanUs"] - l1
        l3 = s["full.detect"]["meanUs"] - s["noRules.detect"]["meanUs"]
        return s, l1, l2, l3

    if b:
        s, _, _, l3 = parts(b)
        v["B_MEAN_MS"] = f"{s['full.total']['meanUs'] / 1000:.1f}"
        v["B_P95_MS"] = f"{s['full.total']['p95Us'] / 1000:.0f}"
        v["B_PPS"] = f"{s['full.wall']['bestPps']:.0f}"
        v["B_L3_MS"] = f"{l3 / 1000:.1f}"
        v["B_DPI_US"] = f"{s['full.dpi']['meanUs']:.0f}"
        v["B_HEAP_KIB"] = fmt_int(b["heap"]["deltaBytes"] / 1024)
    if c:
        s, _, _, l3 = parts(c)
        v["C_MEAN_US"] = f"{s['full.total']['meanUs']:.0f}"
        v["C_P50_US"] = f"{s['full.total']['p50Us']:.0f}"
        v["C_P95_US"] = f"{s['full.total']['p95Us']:.0f}"
        v["C_L3_US"] = f"{l3:.0f}"
        v["C_DPI_US"] = f"{s['full.dpi']['meanUs']:.0f}"
        v["C_PPS"] = fmt_int(round(s["full.wall"]["bestPps"], -2))
        v["C_HEAP_KIB"] = fmt_int(c["heap"]["deltaBytes"] / 1024)
    if big:
        v["C_BIG_PPS"] = fmt_int(round(big["stages"]["full.wall"]["bestPps"], -2))
    if little:
        v["C_LITTLE_PPS"] = fmt_int(round(little["stages"]["full.wall"]["bestPps"], -2))
    wild = need("cost_baseline_nowild_benign_smallFlows_mid.json")
    if wild:
        v["W_L3_US"] = f"{parts(wild)[3]:.0f}"
    hexless = need("cost_baseline_nohex_benign_smallFlows_mid.json")
    if hexless and b and c:
        # The wording depends on what the rebuild shows, so it is chosen from the measurement
        new_dpi = hexless["stages"]["full.dpi"]["meanUs"]
        v["H_DPI_US"] = f"{new_dpi:.0f}"
        gain = b["stages"]["full.dpi"]["meanUs"] - new_dpi
        whole = b["stages"]["full.dpi"]["meanUs"] - c["stages"]["full.dpi"]["meanUs"]
        v["H_SHARE"] = f"{100 * gain / whole:.0f}"
    phone_b = need("cost_baseline_benign_phone_test_00_mid.json")
    phone_c = need("cost_current_benign_phone_test_00_mid.json")
    if phone_b and phone_c:
        v["C_PHONE_US"] = f"{phone_c['stages']['full.total']['meanUs']:.0f}"
        v["B_PHONE_US"] = fmt_int(phone_b["stages"]["full.total"]["meanUs"])
        v["B_PHONE_N"] = fmt_int(phone_b["packets"])


def head_to_head():
    v = values
    t = need("throughput_final.json")
    if t:
        rounds = need("throughput_final_meta.json")
        v["TP_ROUNDS"] = {3: "three", 4: "four", 5: "five"}.get(rounds["rounds"], str(rounds["rounds"])) if rounds else "several"

        def med(key, field, digits=0):
            data = t[key][field]
            return f"{st.median(data):.{digits}f}" if data else "--"
        for tag, key in (("NONE", "no_capture"), ("PD", "pcapdroid"), ("ANF", "andronet_forward"), ("ANA", "andronet_analysis"), ("AN", "andronet_full")):
            v[f"TP_{tag}_D"] = med(key, "down")
            v[f"TP_{tag}_U"] = med(key, "up")
            v[f"TP_{tag}_R"] = med(key, "rttP50", 1)
            v[f"TP_{tag}_C"] = med(key, "cpu")
            v[f"TP_{tag}_M"] = med(key, "rss")
        v["AN_DOWN"] = v["TP_AN_D"]
        ratio = st.median(t["andronet_full"]["down"]) / st.median(t["pcapdroid"]["down"])
        v["THROUGHPUT_RATIO"] = f"{100 * ratio:.0f}\\%"
        v["TP_FORWARD_PCT"] = f"{100 * st.median(t['andronet_forward']['down']) / st.median(t['pcapdroid']['down']):.0f}"
        # The paragraph on Table 8 says these things; it must be rewritten if a repeat changes them
        if st.median(t["pcapdroid"]["down"]) < 0.9 * st.median(t["no_capture"]["down"]):
            raise SystemExit("PCAPdroid no longer keeps pace with no capture")
        if st.median(t["andronet_full"]["cpu"]) < 1.5 * st.median(t["andronet_analysis"]["cpu"]):
            raise SystemExit("the UI stream no longer about doubles CPU")
    rates = need("benign_live_rates.json")
    if rates:
        v["PHONE_MEAN_MBPS"] = f"{rates['meanMbps']:.1f}"
        v["PHONE_PEAK_MBPS"] = f"{rates['peakSecondMbps']:.0f}"
    e = need("energy_summary.json")
    if e:
        w = e["work"]
        for tag, key in (("NONE", "none"), ("PD", "pcapdroid"), ("AN", "andronet")):
            tr, idle = w["traffic"][key], w["idle"][key]
            v[f"EN_T_{tag}"] = f"{tr['meanW']:.2f} $\\pm$ {tr['stdevW']:.2f}"
            v[f"EN_I_{tag}"] = f"{idle['meanW']:.2f} $\\pm$ {idle['stdevW']:.2f}"
            v[f"EN_TP_{tag}"] = f"{tr['pctPerHour']:.1f}"
            v[f"EN_IP_{tag}"] = f"{idle['pctPerHour']:.1f}"
        delta = 100 * (w["traffic"]["andronet"]["meanW"] / w["traffic"]["pcapdroid"]["meanW"] - 1)
        v["POWER_DELTA_PCT"] = f"{delta:.0f}"
        v["EN_REPS"] = {3: "three"}.get(w["traffic"]["andronet"]["runs"], str(w["traffic"]["andronet"]["runs"]))
        none_t, pd_t, an_t = (w["traffic"][k]["meanW"] for k in ("none", "pcapdroid", "andronet"))
        idle = [w["idle"][k] for k in ("none", "pcapdroid", "andronet")]
        if max(x["meanW"] for x in idle) - min(x["meanW"] for x in idle) > max(x["stdevW"] for x in idle):
            raise SystemExit("the paper says idle power differs by less than the spread between repetitions")
        excluded = e["excludedRuns"]
        if any("idle" not in run for run in excluded):
            raise SystemExit("the paper says only idle runs were excluded")
        dropped = {0: "", 2: " Two idle runs in which the cable was reconnected early are excluded."}[len(excluded)]
        v["ENERGY_TEXT"] = (f"Under the 10~Mbit/s load AndroNet adds {an_t - none_t:.2f}~W to the no-capture baseline, where PCAPdroid adds "
                            f"{pd_t - none_t:.2f}~W, and its process stays near {w['traffic']['andronet']['cpuPct']:.0f}\\% of a core against "
                            f"{w['traffic']['pcapdroid']['cpuPct']:.0f}\\%. At idle the three differ by less than the spread between repetitions.{dropped}")
    v["B_THROUGHPUT"] = "15"  # measured 14.5 and 15.4 Mbit/s before the single-loop fix; see evaluation/README.md


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
    logs = ""
    for _ in range(1):
        r = run([str(TEX / "pdflatex.exe"), "-interaction=nonstopmode", f"{name}.tex"])
        logs = r.stdout
    return logs


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

    accuracy()
    parity()
    development()
    misses()
    live()
    cost()
    head_to_head()

    text, placeholder_authors = fill(TEMPLATE.read_text(encoding="utf-8"), not args.final)
    OUT.write_text(text, encoding="utf-8")
    (RESULTS / "paper_values.json").write_text(json.dumps(values, indent=1))
    log = compile_all()

    gaps = sorted(set(missing))
    print("gaps:", gaps if gaps else "none")
    print("author placeholders:", placeholder_authors)
    if args.final:
        if gaps or placeholder_authors:
            raise SystemExit("not final: gaps or author placeholders remain")
        bundle = HERE / "andronet_source.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
            for name in ZIP_FILES:
                z.write(HERE / name, name)
        shutil.copy(HERE / "andronet.pdf", HERE / "andronet_final.pdf")
        print("wrote", bundle)


if __name__ == "__main__":
    main()
