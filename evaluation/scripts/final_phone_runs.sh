#!/usr/bin/env bash
# Runs the phone measurements one after another, so that no experiment disturbs another.
# Energy is separate: it needs the USB cable out (see energy_start.py).
cd "$(dirname "$0")"
: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone under test}"
R=../results
echo "== visibility $(date)"; python visibility_probe.py > $R/visibility.log 2>&1; tail -3 $R/visibility.log
echo "== annotation $(date)"; python annotation_check.py > $R/annotation.log 2>&1; tail -7 $R/annotation.log
T=../traces/dev/benign_smallFlows.pcap
P=../results/private/benign_phone_test/benign_phone_test_00.pcapng
echo "== cost $(date)"
python run_cost.py --build baseline --trace $T --limit 14300 --repeat 2 --cpus f0 --tag mid 2>&1 | tail -1
python run_cost.py --build current --trace $T --limit 14300 --repeat 3 --cpus f0 --tag mid 2>&1 | tail -1
python run_cost.py --build current --trace $T --limit 14300 --repeat 3 --cpus 100 --tag big 2>&1 | tail -1
python run_cost.py --build current --trace $T --limit 14300 --repeat 3 --cpus 0f --tag little 2>&1 | tail -1
python run_cost.py --build current --trace $T --limit 14300 --repeat 3 --tag sched 2>&1 | tail -1
python run_cost.py --build current --trace $P --limit 20000 --repeat 3 --cpus f0 --tag mid 2>&1 | tail -1
python run_cost.py --build baseline --trace $P --limit 3000 --repeat 1 --cpus f0 --tag mid 2>&1 | tail -1
echo "== throughput $(date)"
python throughput_final.py --rounds 5 --mb 50 --only no_capture,pcapdroid,andronet_forward,andronet_analysis,andronet_full > $R/throughput_final.log 2>&1
tail -8 $R/throughput_final.log
echo "== done $(date)"
