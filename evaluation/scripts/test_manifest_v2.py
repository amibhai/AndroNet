"""Ground truth for the second held-out set, written before any detector saw these files.

Selected by rule, from names and publisher descriptions alone, with no capture opened:
  - every RAT in Android Mischief Dataset v2,
  - every StopDDoS capture of 50 MB or less not used earlier,
  - every Bousseaden PCAP-ATTACK capture not used earlier, of which only the DGA backdoor falls in a
    class AndroNet targets. The Windows-domain techniques stay in on purpose, scored apart, so that
    results also show what is out of reach.

"expect" lists the alerts that count as detecting a capture. It was fixed before the first replay.
"""

# Any of these on a RAT capture counts: the design claims to catch implants by their signatures, by
# what their flows open with, by protocol mismatch, by timing and by their DNS behaviour.
RAT = ["FLOW-001", "FLOW-002", "FLOW-003", "FLOW-004", "FLOW-005", "APP-001",
       "MAL-001", "MAL-002", "MAL-003", "C2-001", "C2-002", "C2-003", "C2-004"]
FLOOD = ["L1:DISTRIBUTED_FLOOD", "L1:SYN_FLOOD", "L1:CONNECTION_FLOOD", "RULE-010"]

MISCHIEF = "Babayeva, Android Mischief Dataset v2"
STOPDDOS = "StopDDoS packet captures"
BOUSSEADEN = "Bousseaden, PCAP-ATTACK"

ATTACKS = {
    "atk_fresh_rat_androidtester": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_droidjack": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_hawkshaw": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_spymax": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_androrat": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_saefko": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_ahmyth": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},
    "atk_fresh_rat_cli_androrat": {"class": "android_rat", "expect": RAT, "source": MISCHIEF},

    "atk_fresh_flood_tcp_synack_reflection": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_tcp_syn_amp": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_dnsany": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_ubnt": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_bacnet": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_isakmp": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_manyprotocols": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_memcached_ntp_cldap": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_snmp": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_dns_rrsig_fragmented": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_ip_randomproto": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_tcp_dominate": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_fragmented": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_null": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},
    "atk_fresh_flood_udp_rdm": {"class": "flood", "expect": FLOOD, "source": STOPDDOS},

    "atk_fresh_c2_foudre_dga": {"class": "dga_backdoor", "expect": ["FLOW-005", "L1:DNS_TUNNELING", "RULE-004", "C2-002"], "source": BOUSSEADEN},

    # No detector targets these Windows-domain techniques
    "atk_fresh_win_psloggedon": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_netshareenum": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_rpcdump": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_samr": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_zerologon": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_sigred": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_wmi": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_dcom": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_sharprdp": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_smbexec": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_skeleton": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_zerologon_scan": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_eventservice": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_spoolsample": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_kerbrute": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_masterkey": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_backupkey": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_dcshadow": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_dcsync": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_pwdreset": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
    "atk_fresh_win_smbghost": {"class": "untargeted", "expect": [], "source": BOUSSEADEN},
}

# Benign traffic for this set is phone traffic recorded after the freeze:
#   benign_fresh_pixel_*, benign_fresh_samsung_* (browsing and real apps), scored here; the 24-hour
#   run on a person's own phone keeps only alert counts and is scored by soak.py.
BENIGN = {}
