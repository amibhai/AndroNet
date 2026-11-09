#!/bin/sh
# The measurements of the second evaluation cycle, in order, on the frozen builds.
#
#   sh second_cycle.sh sessions   # phone: browsing and app sessions, live attacks, visibility, export check
#   sh second_cycle.sh amended    # phone: quiet connections on the frozen build and on v1.5.1, then v1.5.1 live
#   sh second_cycle.sh replay [host|phone]   # desktop and phone: frozen v1.4.0, v1.5.0 and v1.5.1 on the fresh captures
#   sh second_cycle.sh cost       # phone: per-layer cost on each core class
#   sh second_cycle.sh soak       # phone: starts a day of real use, on an app with empty profiles
#   ANDROID_SERIAL=<serial> sh second_cycle.sh device <tag>   # another phone, already on the lab network
#
# Throughput runs apart, with the laptop idle: python throughput_final.py --rounds 5 --mb 50 --tag v15final
cd "$(dirname "$0")" || exit 1
export PYTHONIOENCODING=utf-8 MSYS_NO_PATHCONV=1   # set ANDROID_SERIAL as well when several phones are attached
PKG=com.example.packet_analyzer.eval
RESULTS=../results
FRESH=D:/andronet_eval/fresh   # not /d/...: Windows Python would read that as a folder on drive C
SESSIONS=$RESULTS/private/second_cycle

python freeze_v15.py --check || exit 1

# A failed step usually means the phone has gone, so the steps after it would measure nothing
step() {
    echo "=== $(date +%H:%M) $*"
    "$@" || { echo "=== FAILED: $*"; exit 1; }
}

# A step that has its result already is skipped, so that a block cut short can carry on from there
once() {
    if [ -f "$RESULTS/$1" ]; then
        echo "=== already have $1"
    else
        shift
        step "$@"
    fi
}

case "$1" in
sessions)
    # Empty app profiles, so that learning a phone's apps counts against the result
    adb shell "am force-stop $PKG; pm clear $PKG; appops set $PKG ACTIVATE_VPN allow; appops set $PKG MANAGE_EXTERNAL_STORAGE allow; pm grant $PKG android.permission.POST_NOTIFICATIONS"
    step python benign_session.py --list fresh --tag fresh_pixel --apps
    step python benign_session.py --list fresh --tag fresh_pixel_noid --apps --no-identity
    step python live_attacks.py --tag v15final
    step python live_attacks.py --tag v15noid --no-identity
    step python visibility_probe.py
    step python annotation_check.py
    ;;
amended)
    adb shell "svc wifi enable"
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        adb shell "ip -4 addr show wlan0" | grep -q "inet 192.168.1." && break
        sleep 5
    done
    adb shell "ip -4 addr show wlan0" | grep -q "inet 192.168.1." || { echo "=== FAILED: no Wi-Fi on the lab network"; exit 1; }
    step python guard_check.py
    once idle_probe_pixel_none.json python idle_probe.py --mode none --tag pixel_none
    once idle_probe_pixel_v150.json python idle_probe.py --mode andronet --tag pixel_v150
    if ! adb shell "dumpsys package $PKG" | grep -q "versionName=1.5.1"; then
        adb install -r ../build/andronet-eval-arm64-v151.apk
        adb shell "am force-stop $PKG; pm clear $PKG; appops set $PKG ACTIVATE_VPN allow; appops set $PKG MANAGE_EXTERNAL_STORAGE allow; pm grant $PKG android.permission.POST_NOTIFICATIONS"
    fi
    once idle_probe_pixel_v151.json python idle_probe.py --mode andronet --tag pixel_v151
    once idle_probe_pixel_pcapdroid.json python idle_probe.py --mode pcapdroid --tag pixel_pcapdroid
    once live_attacks_v151final.json python live_attacks.py --tag v151final
    once live_attacks_v151noid.json python live_attacks.py --tag v151noid --no-identity
    L=dns_failed_lookups
    once live_attacks_v151lookups.json python live_attacks.py --tag v151lookups --only $L,$L,$L,$L,$L,$L,$L,$L,$L,$L
    once visibility.json python visibility_probe.py
    once annotation_check.json python annotation_check.py
    ;;
soak)
    adb shell "am force-stop $PKG; pm clear $PKG; appops set $PKG ACTIVATE_VPN allow; appops set $PKG MANAGE_EXTERNAL_STORAGE allow; pm grant $PKG android.permission.POST_NOTIFICATIONS"
    step python soak.py start --tag pixel
    ;;
device)
    TAG="$2"
    adb install -r ../build/andronet-eval-arm64-v151.apk
    adb shell "am force-stop $PKG; pm clear $PKG; appops set $PKG ACTIVATE_VPN allow; appops set $PKG MANAGE_EXTERNAL_STORAGE allow; pm grant $PKG android.permission.POST_NOTIFICATIONS"
    # The session needs the screen on and unlocked, and this lasts only while the phone is plugged in.
    # Some vendors report a laptop's port as AC power, so "usb" alone would not hold.
    adb shell "svc power stayon true; input keyevent KEYCODE_WAKEUP"
    step python device_info.py "$TAG"
    step python guard_check.py
    once "live_attacks_$TAG.json" python live_attacks.py --tag "$TAG"
    once "benign_live_fresh_$TAG.json" python benign_session.py --list fresh --tag "fresh_$TAG" --apps
    mkdir -p "$SESSIONS"
    "/c/Program Files/Wireshark/mergecap.exe" -w "$SESSIONS/benign_fresh_$TAG.pcapng" "$RESULTS"/private/benign_phone_fresh_"$TAG"/*.pcapng
    once "cost_v151_benign_smallFlows_$TAG.json" python run_cost.py --build v151 --trace ../traces/dev/benign_smallFlows.pcap --tag "$TAG"
    once "throughput_$TAG.json" python throughput_final.py --rounds 2 --mb 50 --only no_capture,andronet_full --tag "$TAG"
    adb shell "svc power stayon false"
    ;;
replay)
    # "replay host" or "replay phone" runs one half. The paper checks that both halves agree, so run
    # the other half before building it, on the same captures.
    PART="${2:-both}"
    mkdir -p "$SESSIONS"
    "/c/Program Files/Wireshark/mergecap.exe" -w "$SESSIONS/benign_fresh_pixel.pcapng" "$RESULTS"/private/benign_phone_fresh_pixel/*.pcapng
    if [ "$PART" != phone ]; then
        for pair in "current v15" "v140 v140" "v151 v151"; do
            set -- $pair
            step python run_replay.py --build "$1" --set fresh --where host --thresholds shipped --view root --extra "$FRESH" --extra "$SESSIONS" --tag "$2_fresh_host"
            step python flow_check.py "$RESULTS/alerts_$2_fresh_host.tsv" "$2_fresh_host"
        done
        step python run_replay.py --build current --set test --where host --thresholds shipped --view root --extra "$RESULTS/private/benign_phone_test" --extra D:/andronet_eval/traces_test_large --tag v15_dev_host
        step python run_replay.py --build v151 --set test --where host --thresholds shipped --view root --extra "$RESULTS/private/benign_phone_test" --extra D:/andronet_eval/traces_test_large --tag v151_dev_host
        step python check_fingerprints.py "$RESULTS/private/merged/benign_phone_dev3.pcapng" "$RESULTS/private/benign_phone_test/benign_phone_test_00.pcapng" D:/andronet_eval/traces_test_large/benign_bigFlows.pcap
    fi
    if [ "$PART" != host ]; then
        for pair in "current v15" "v140 v140" "v151 v151"; do
            set -- $pair
            step python run_replay.py --build "$1" --set fresh --where phone --thresholds shipped --view root --extra "$FRESH" --extra "$SESSIONS" --tag "$2_fresh_phone"
            step python flow_check.py "$RESULTS/alerts_$2_fresh_phone.tsv" "$2_fresh_phone"
        done
        step python score.py --fresh "$RESULTS/accuracy_v15_fresh_phone.json" "$RESULTS/accuracy_v140_fresh_phone.json"
    fi
    ;;
cost)
    for pair in "f0 v151mid" "100 v151big" "0f v151little"; do
        set -- $pair
        step python run_cost.py --build v151 --trace ../traces/dev/benign_smallFlows.pcap --cpus "$1" --tag "$2"
    done
    ;;
esac
