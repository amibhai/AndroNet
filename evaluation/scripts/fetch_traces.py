#!/usr/bin/env python3
"""Downloads the third-party captures used for evaluation.

The split was fixed before any detector was run on these files:
  dev/   tuning: benign background only; attack traffic for tuning comes from lab/gen_dev_traces.py
  test/  held out until the code freeze: every file below was captured by someone else

Labels come from the publisher's own description of each capture.
"""
import pathlib
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1] / "traces"
SANDERS = "https://raw.githubusercontent.com/chrissanders/packets/master/"
WIRESHARK = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/"
BOUSSEADEN = "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/"
STOPDDOS = "https://raw.githubusercontent.com/StopDDoS/packet-captures/master/"
TCPREPLAY = "https://s3.amazonaws.com/tcpreplay-pcap-files/"
PPA = "https://raw.githubusercontent.com/markofu/pcaps/master/PracticalPacketAnalysis/ppa-capture-files/"
ZEEK = "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/"

FILES = {
    # ---- development: benign background ----
    "dev/benign_smallFlows.pcap": TCPREPLAY + "smallFlows.pcap",
    # ---- held-out test: third-party attack captures ----
    "test/atk_portscan_synscan.pcapng": SANDERS + "synscan.pcapng",
    "test/atk_portscan_ppa.pcap": PPA + "portscan.pcap",
    "test/nmap_captures.zip": WIRESHARK + "NMap-Captures.zip",
    "test/atk_synflood_spoofed.pcap": STOPDDOS + "pkt.TCP.synflood.spoofed.pcap",
    "test/atk_arp_poison.pcapng": SANDERS + "arppoison.pcapng",
    "test/atk_sqli_dvwa.pcapng": SANDERS + "http_dvwa_sqlinjection.pcapng",
    "test/atk_sqli_dvwa_passwords.pcapng": SANDERS + "http_dvwa_sqlinjection_passwords.pcapng",
    "test/atk_traversal_dvwa.pcapng": SANDERS + "http_dvwa_directorytraversal.pcapng",
    "test/atk_dnstunnel_remoteshell.pcap": WIRESHARK + "dns-remoteshell.pcap",
    "test/atk_dnstunnel_txt_c2.pcap": BOUSSEADEN + urllib.parse.quote("Command and Control/cmds over dns txt queries and reponses.pcap"),
    "test/atk_meterpreter_rdp_tunnel.pcapng": BOUSSEADEN + urllib.parse.quote("Command and Control/rdp_tunneling_meterpreter_portfwd.pcapng"),
    "test/atk_icmp_flood_large.pcap": STOPDDOS + "pkt.ICMP.largeempty.pcap",
    "test/atk_rat_infected.pcapng": SANDERS + "ratinfected.pcapng",
    "test/atk_aurora_exploit.pcapng": SANDERS + "aurora.pcapng",
    "test/atk_cryptowall_c2.pcapng": SANDERS + "cryptowall4_c2.pcapng",
    "test/atk_sessionhijack.pcapng": SANDERS + "sessionhijacking.pcapng",
    "test/atk_dcerpc_scan.pcapng": BOUSSEADEN + "Discovery/discovery_scan_dcerpc_endpoint_mapper.pcapng",
    "test/atk_psexec_lateral.pcapng": BOUSSEADEN + urllib.parse.quote("Lateral Movement/LM_psexec_smb_dcerpc_epm_svcctl.pcapng"),
    "test/atk_ms04_011_exploit.cap": WIRESHARK + "dssetup_DsRoleUpgradeDownlevelServer_MS04-011_exploit.cap",
    "test/atk_ftp_bruteforce_zeek.pcap": ZEEK + "ftp/bruteforce.pcap",
    "test/atk_ssh_guessing_zeek.pcap": ZEEK + "ssh/sshguess.pcap",
    "test/atk_nmap_version_zeek.pcap": ZEEK + "nmap-vsn.pcap",
    "test/benign_ssh_zeek.pcap": ZEEK + "ssh/ssh.pcap",
    "test/benign_irc_zeek.pcap": ZEEK + "irc-basic.pcap",
    "test/benign_smb1_suricata.pcap": "https://raw.githubusercontent.com/OISF/suricata-verify/master/tests/smb1-01/smb1.pcap",
    # ---- held-out test: third-party benign captures ----
    "test/benign_bigFlows.pcap": TCPREPLAY + "bigFlows.pcap",
    "test/benign_lotsofweb.pcapng": SANDERS + "lotsofweb.pcapng",
    "test/benign_http_espn.pcapng": SANDERS + "http_espn.pcapng",
    "test/benign_smb_win10.pcapng": WIRESHARK + "smb-on-windows-10.pcapng",
    "test/benign_irc_skype.cap": WIRESHARK + "SkypeIRC.cap",
    "test/benign_dhcp.pcap": WIRESHARK + "dhcp.pcap",
    "test/benign_telnet.pcap": WIRESHARK + "telnet-cooked.pcap",
    "test/benign_http_gzip.cap": WIRESHARK + "http_gzip.cap",
}


def fetch(rel, url):
    dest = ROOT / rel
    if dest.exists() and dest.stat().st_size > 0:
        return "cached", dest.stat().st_size
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (research; AndroNet evaluation)"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    tmp.replace(dest)
    return "ok", dest.stat().st_size


def main():
    fails = 0
    for rel, url in FILES.items():
        if len(sys.argv) > 1 and sys.argv[1] not in rel:
            continue
        try:
            status, size = fetch(rel, url)
            print(f"{status:7s} {size:>12d} {rel}", flush=True)
        except Exception as e:
            fails += 1
            print(f"FAILED  {rel}: {e}", flush=True)
    nm = ROOT / "test/nmap_captures.zip"
    if nm.exists():
        with zipfile.ZipFile(nm) as z:
            for i in z.infolist():
                name = pathlib.PurePosixPath(i.filename).name
                if name.lower().endswith((".pcap", ".cap", ".pcapng")) and i.file_size > 0:
                    out = ROOT / "test" / ("atk_nmap_" + name.replace(" ", "_"))
                    if not out.exists():
                        out.write_bytes(z.read(i))
                    print("extract", out.name, out.stat().st_size)
    print("failures:", fails)


if __name__ == "__main__":
    main()
