#!/usr/bin/env bash
# Finishes the phone measurements after the first chain stopped: the export-fix APK and its checks,
# the visibility probe, the wildcard cost experiment, and then all throughput rounds. Keep the laptop
# otherwise idle during the throughput part: it serves those transfers.
cd "$(dirname "$0")"
: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone under test}"
R=../results
PKG=com.example.packet_analyzer.eval
adb wait-for-device
echo "== install export fix $(date)"
adb install -r ../build/andronet-eval-arm64.apk 2>&1 | tail -1
adb shell "appops set $PKG ACTIVATE_VPN allow; appops set $PKG MANAGE_EXTERNAL_STORAGE allow; pm grant $PKG android.permission.POST_NOTIFICATIONS"
echo "== annotation $(date)"; python annotation_check.py > $R/annotation.log 2>&1; tail -7 $R/annotation.log
python check_pcapng.py $R/private/annotation_check.pcapng
echo "== visibility $(date)"; python visibility_probe.py > $R/visibility.log 2>&1; tail -4 $R/visibility.log
T=../traces/dev/benign_smallFlows.pcap
echo "== wildcard cost $(date)"
python run_cost.py --build baseline_nowild --trace $T --limit 14300 --repeat 2 --cpus f0 --tag mid 2>&1 | tail -1
echo "== throughput $(date)"
python throughput_final.py --rounds 5 --mb 50 --only no_capture,pcapdroid,andronet_forward,andronet_analysis,andronet_full > $R/throughput_final.log 2>&1
tail -8 $R/throughput_final.log
echo "== done $(date)"
