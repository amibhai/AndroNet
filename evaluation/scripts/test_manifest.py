"""Ground truth for the held-out set, written before any detector saw these files.

Each attack capture is labelled from its publisher's description. "expect" lists the alerts that
count as detecting it. A capture with no entry in "expect" is a threat no AndroNet detector targets:
it is scored separately and kept in the set on purpose, so that results also show what is missed.
"source" is the publisher, reported in the paper's data table.
"""

ATTACKS = {
    # Scans
    "atk_portscan_synscan": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Sanders, Practical Packet Analysis"},
    "atk_portscan_ppa": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Sanders, Practical Packet Analysis (1st ed.)"},
    "atk_wsnmap_standard_scan": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Wireshark sample captures"},
    "atk_wsnmap_OS_scan": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Wireshark sample captures"},
    "atk_wsnmap_OS_scan_succesful": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Wireshark sample captures"},
    "atk_wsnmap_ACK_scan_on_port_80": {"class": "port_scan_single_port", "expect": [], "source": "Wireshark sample captures"},
    "atk_wsnmap_ACK_scan_on_port_80_2": {"class": "port_scan_single_port", "expect": [], "source": "Wireshark sample captures"},
    "atk_wsnmap_zombie_scan": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Wireshark sample captures"},
    "atk_nmap_version_zeek": {"class": "port_scan", "expect": ["L1:PORT_SCAN", "RULE-001"], "source": "Zeek test suite"},
    # Floods
    "atk_synflood_spoofed": {"class": "syn_flood", "expect": ["L1:SYN_FLOOD"], "source": "StopDDoS packet captures"},
    "atk_icmp_flood_large": {"class": "icmp_abuse", "expect": ["RULE-010", "L1:COVERT_CHANNEL"], "source": "StopDDoS packet captures"},
    # LAN manipulation
    "atk_arp_poison": {"class": "arp_spoof", "expect": ["L1:ARP_SPOOFING"], "source": "Sanders, Practical Packet Analysis"},
    # Web attacks
    "atk_sqli_dvwa": {"class": "sql_injection", "expect": ["EXP-001", "RULE-002"], "source": "Sanders, Practical Packet Analysis"},
    "atk_sqli_dvwa_passwords": {"class": "sql_injection", "expect": ["EXP-001", "RULE-002"], "source": "Sanders, Practical Packet Analysis"},
    "atk_traversal_dvwa": {"class": "path_traversal", "expect": ["EXP-002"], "source": "Sanders, Practical Packet Analysis"},
    # Tunnels and C2
    "atk_dnstunnel_remoteshell": {"class": "dns_tunnel", "expect": ["L1:DNS_TUNNELING", "RULE-004"], "source": "Wireshark sample captures"},
    "atk_dnstunnel_txt_c2": {"class": "dns_tunnel", "expect": ["L1:DNS_TUNNELING", "RULE-004"], "source": "Bousseaden, PCAP-ATTACK"},
    "atk_meterpreter_rdp_tunnel": {"class": "meterpreter", "expect": ["MAL-001"], "source": "Bousseaden, PCAP-ATTACK"},
    # Login guessing
    "atk_ftp_bruteforce_zeek": {"class": "bruteforce", "expect": ["RULE-005"], "source": "Zeek test suite"},
    "atk_ssh_guessing_zeek": {"class": "bruteforce", "expect": ["RULE-005", "BRUTE-001"], "source": "Zeek test suite"},
    # Worm
    "atk_wannacry_eternalblue": {"class": "smb_worm", "expect": ["NET-001", "MAL-002"], "source": "Szili, via Malware-Traffic-Analysis.net"},
    # No detector targets these
    "atk_ms04_011_exploit": {"class": "untargeted", "expect": [], "source": "Wireshark sample captures"},
    "atk_rat_infected": {"class": "untargeted", "expect": [], "source": "Sanders, Practical Packet Analysis"},
    "atk_aurora_exploit": {"class": "untargeted", "expect": [], "source": "Sanders, Practical Packet Analysis"},
    "atk_cryptowall_c2": {"class": "untargeted", "expect": [], "source": "Sanders, Practical Packet Analysis"},
    "atk_sessionhijack": {"class": "untargeted", "expect": [], "source": "Sanders, Practical Packet Analysis"},
    "atk_dcerpc_scan": {"class": "untargeted", "expect": [], "source": "Bousseaden, PCAP-ATTACK"},
    "atk_psexec_lateral": {"class": "untargeted", "expect": [], "source": "Bousseaden, PCAP-ATTACK"},
}

BENIGN = {
    "benign_bigFlows": {"kind": "enterprise link", "source": "tcpreplay sample captures"},
    "benign_lotsofweb": {"kind": "web browsing", "source": "Sanders, Practical Packet Analysis"},
    "benign_http_espn": {"kind": "web browsing", "source": "Sanders, Practical Packet Analysis"},
    "benign_http_gzip": {"kind": "web browsing", "source": "Wireshark sample captures"},
    "benign_smb_win10": {"kind": "file sharing", "source": "Wireshark sample captures"},
    "benign_smb1_suricata": {"kind": "file sharing", "source": "Suricata test suite"},
    "benign_ssh_zeek": {"kind": "remote login", "source": "Zeek test suite"},
    "benign_telnet": {"kind": "remote login", "source": "Wireshark sample captures"},
    "benign_irc_skype": {"kind": "chat", "source": "Wireshark sample captures"},
    "benign_irc_zeek": {"kind": "chat", "source": "Zeek test suite"},
    "benign_dhcp": {"kind": "address assignment", "source": "Wireshark sample captures"},
    # "benign_phone_test*" is the Pixel 8 browsing session captured by AndroNet after the freeze
}
