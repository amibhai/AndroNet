#!/usr/bin/env python3
"""Downloads the second held-out set. Packet captures only: the Android Mischief folders also hold
each RAT's APK, and those are never fetched.

  python fetch_fresh.py <empty directory>

Files are saved under the names test_manifest_v2.py uses, and their hashes are recorded, so that the
set is fixed before any replay. Nothing here opens a capture.
"""
import hashlib
import json
import pathlib
import sys
import urllib.parse
import urllib.request

from test_manifest_v2 import ATTACKS

MISCHIEF = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/"
STOPDDOS = "https://raw.githubusercontent.com/StopDDoS/packet-captures/master/"
BOUSSEADEN = "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/"

SOURCES = {
    "atk_fresh_rat_androidtester": MISCHIEF + "RAT01_AndroidTester/RAT01_AndroidTester.pcap",
    "atk_fresh_rat_droidjack": MISCHIEF + "RAT02_DroidJack/RAT02_DroidJack.pcap",
    "atk_fresh_rat_hawkshaw": MISCHIEF + "RAT03_HawkShaw/RAT03_HawkShaw.pcap",
    "atk_fresh_rat_spymax": MISCHIEF + "RAT04_SpyMAX/RAT04_SpyMAX.pcap",
    "atk_fresh_rat_androrat": MISCHIEF + "RAT05_AndroRAT/RAT05_AndroRAT.pcap",
    "atk_fresh_rat_saefko": MISCHIEF + "RAT06_Saefko/RAT06_Saefko.pcap",
    "atk_fresh_rat_ahmyth": MISCHIEF + "RAT07_AhMyth/RAT07_AhMyth.pcap",
    "atk_fresh_rat_cli_androrat": MISCHIEF + "RAT08_cli_AndroRAT/RAT08_cli_AndroRAT.pcap",

    "atk_fresh_flood_tcp_synack_reflection": STOPDDOS + "amp.TCP.reflection.SYNACK.pcap",
    "atk_fresh_flood_tcp_syn_amp": STOPDDOS + "amp.TCP.syn.optionallyACK.optionallysamePort.pcapng",
    "atk_fresh_flood_udp_dnsany": STOPDDOS + "amp.UDP.DNSANY.pcap",
    "atk_fresh_flood_udp_ubnt": STOPDDOS + "amp.UDP.UBNT.src10001.pcapng",
    "atk_fresh_flood_udp_bacnet": STOPDDOS + "amp.UDP.bacnet.IOT.37810.pcapng",
    "atk_fresh_flood_udp_isakmp": STOPDDOS + "amp.UDP.isakmp.pcap",
    "atk_fresh_flood_udp_manyprotocols": STOPDDOS + "amp.UDP.manyprotocols.pcapng",
    "atk_fresh_flood_udp_memcached_ntp_cldap": STOPDDOS + "amp.UDP.memcached.ntp.cldap.pcap",
    "atk_fresh_flood_udp_snmp": STOPDDOS + "amp.UDP.snmp.src161.pcapng",
    "atk_fresh_flood_dns_rrsig_fragmented": STOPDDOS + "amp.dns.RRSIG.fragmented.pcap",
    "atk_fresh_flood_ip_randomproto": STOPDDOS + "pkt.IPV4.randomprotofield.pcap",
    "atk_fresh_flood_tcp_dominate": STOPDDOS + "pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng",
    "atk_fresh_flood_udp_fragmented": STOPDDOS + "pkt.UDP.fragmented.pcap",
    "atk_fresh_flood_udp_null": STOPDDOS + "pkt.UDP.null.pcapng",
    "atk_fresh_flood_udp_rdm": STOPDDOS + "pkt.UDP.rdm.fixedlength.pcapng",

    "atk_fresh_c2_foudre_dga": BOUSSEADEN + "Command and Control/C2_Foudre_Backdoor_DGA.pcapng",

    "atk_fresh_win_psloggedon": BOUSSEADEN + "Discovery/Discovery_PsLoggedOn_remotelocalusers_enum_winreg_lsarpc_dcerpc_smb.pcapng",
    "atk_fresh_win_netshareenum": BOUSSEADEN + "Discovery/Discovery_dcerp_srvsvc_NetShareEnum.pcapng",
    "atk_fresh_win_rpcdump": BOUSSEADEN + "Discovery/Discovery_impacket_rpcdump.pcapng",
    "atk_fresh_win_samr": BOUSSEADEN + "Discovery/Discovery_privgroups_domain_admins_samr_lookupnames_req.pcapng",
    "atk_fresh_win_zerologon": BOUSSEADEN + "Lateral Movement/CVE-2020-1472_Zerologon_RPC_NetLogon_NullChallenge_SecChan_6_from_nonDC_to_DC.pcapng",
    "atk_fresh_win_sigred": BOUSSEADEN + "Lateral Movement/Exploit_DoS_cve-2020-1350_dns_sig_maxspl0it.pcapng",
    "atk_fresh_win_wmi": BOUSSEADEN + "Lateral Movement/LM_WMI_ProcessCallCreate.pcapng",
    "atk_fresh_win_dcom": BOUSSEADEN + "Lateral Movement/LM_dcom_mmc20.application_dcerpc.pcapng",
    "atk_fresh_win_sharprdp": BOUSSEADEN + "Lateral Movement/LM_rdp_sharprdp.pcapng",
    "atk_fresh_win_smbexec": BOUSSEADEN + "Lateral Movement/LM_smbexec_smb_dcerpc_svcctl_epm.pcapng",
    "atk_fresh_win_skeleton": BOUSSEADEN + "Lateral Movement/lm_mimikazt_skeleton_kerberos_rc4_etype.pcapng",
    "atk_fresh_win_zerologon_scan": BOUSSEADEN + "Lateral Movement/zerologon_mimikatz_ntlm_privacy_scan_and_exploit_encrypted.pcapng",
    "atk_fresh_win_eventservice": BOUSSEADEN + "Evasion/DE_byt3bl33d3r_remote_eventservice_crash.pcapng",
    "atk_fresh_win_spoolsample": BOUSSEADEN + "CredAccess/CA_LM_SpoolSample_SMB_BiAuth.pcapng",
    "atk_fresh_win_kerbrute": BOUSSEADEN + "CredAccess/CA_kerbrute_passwordspray_kerberos_AS-REQ.pcapng",
    "atk_fresh_win_masterkey": BOUSSEADEN + "CredAccess/CA_masterkey_rpc_protectedstorage.pcapng",
    "atk_fresh_win_backupkey": BOUSSEADEN + "CredAccess/CredAccess_BackupMasterKey_LSARPC_43_RetrievePrivateData.pcapng",
    "atk_fresh_win_dcshadow": BOUSSEADEN + "CredAccess/DCShadow_add_primarygroupid_512_to_std_account.pcapng",
    "atk_fresh_win_dcsync": BOUSSEADEN + "CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng",
    "atk_fresh_win_pwdreset": BOUSSEADEN + "CredAccess/Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng",
    "atk_fresh_win_smbghost": BOUSSEADEN + "PrivEsc/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng",
}


def main():
    if set(SOURCES) != set(ATTACKS):
        raise SystemExit(f"manifest and sources differ: {set(SOURCES) ^ set(ATTACKS)}")
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name, url in SOURCES.items():
        target = out / (name + "." + url.rsplit(".", 1)[-1])
        if not target.exists():
            print("fetching", name, flush=True)
            parts = urllib.parse.urlsplit(url)
            request = urllib.request.Request(urllib.parse.urlunsplit(parts._replace(path=urllib.parse.quote(parts.path))),
                                             headers={"User-Agent": "Mozilla/5.0"})
            try:
                with urllib.request.urlopen(request, timeout=300) as response, open(target, "wb") as f:
                    while chunk := response.read(1 << 20):
                        f.write(chunk)
            except Exception as e:
                print("FAILED", name, e, flush=True)
                target.unlink(missing_ok=True)
                continue
        hashes[target.name] = {"sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "bytes": target.stat().st_size, "url": url}
    results = pathlib.Path(__file__).resolve().parents[1] / "results" / "fresh_set.json"
    results.write_text(json.dumps(hashes, indent=1))
    print(len(hashes), "of", len(SOURCES), "captures,", sum(h["bytes"] for h in hashes.values()) // (1 << 20), "MiB")


if __name__ == "__main__":
    main()
