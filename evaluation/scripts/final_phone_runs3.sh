#!/usr/bin/env bash
# Repeats the visibility probe with raw scans only, and costs v1.3.0 with only its hex formatting
# replaced. Run after the throughput rounds.
cd "$(dirname "$0")"
: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone under test}"
R=../results
adb wait-for-device
mkdir -p $R/superseded; cp $R/visibility.json $R/superseded/visibility_first.json
echo "== visibility $(date)"; python visibility_probe.py > $R/visibility.log 2>&1; tail -4 $R/visibility.log
T=../traces/dev/benign_smallFlows.pcap
echo "== hex cost $(date)"
python run_cost.py --build baseline_nohex --trace $T --limit 14300 --repeat 2 --cpus f0 --tag mid 2>&1 | tail -1
echo "== done $(date)"
