#!/system/bin/sh
# Self-running battery measurement. Runs on the phone so that the USB cable can be out: charging
# current would otherwise swamp the signal. Started by scripts/energy_start.py.
#
# Each run: start the condition, settle past AndroNet's 60 s learning period, then log battery
# current and voltage every second under a fixed workload. Conditions rotate in a Latin square
# so that drift over the session (temperature, charge level) does not favour any of them.
#
# A fourth argument "dry" checks the whole sequence with the cable in: short runs, one repetition.

HOST=$1
MEASURE=${2:-150}
RATE=${3:-10}
DRY=$4
D=/data/local/tmp/andronet_eval
OUT=$D/energy_samples.csv
RUNS=$D/energy_runs.csv
EVAL_PKG=com.example.packet_analyzer.eval
EVAL_MAIN=$EVAL_PKG/com.example.packet_analyzer.MainActivity
PD=com.emanuelef.remote_capture
PS=/sys/class/power_supply/battery
SETTLE=65
[ "$DRY" = "dry" ] && SETTLE=5

now_ms() { date +%s%3N; }
on_battery() { dumpsys battery | grep -q 'USB powered: false' && dumpsys battery | grep -q 'AC powered: false'; }
tun_count() { ip -o -4 addr show | grep -c ' tun'; }

stop_all() {
    am force-stop $EVAL_PKG
    am force-stop $PD
}

start_condition() {
    stop_all
    sleep 3
    case "$1" in
        none) ;;
        andronet)
            for attempt in 1 2 3; do
                am start -n $EVAL_MAIN --es andronet_action start_vpn >/dev/null
                sleep 8
                [ "$(tun_count)" != "0" ] && break
                am force-stop $EVAL_PKG
                sleep 2
            done
            ;;
        pcapdroid)
            for attempt in 1 2 3; do
                am start -e action start -e pcap_dump_mode none -n $PD/.activities.CaptureCtrl >/dev/null
                sleep 3
                input tap 770 1392   # PCAPdroid's per-request consent dialog
                sleep 5
                [ "$(tun_count)" != "0" ] && break
                am force-stop $PD
                sleep 2
            done
            ;;
    esac
    input keyevent KEYCODE_HOME
}

pid_for() {
    case "$1" in
        andronet) pidof $EVAL_PKG ;;
        pcapdroid) pidof $PD ;;
    esac
}

jiffies() {
    [ -z "$1" ] && { echo 0; return; }
    awk '{print $14+$15}' /proc/$1/stat 2>/dev/null || echo 0
}

run_one() {
    cond=$1
    work=$2
    rep=$3
    start_condition "$cond"
    sleep $SETTLE
    tun=$(tun_count)
    pid=$(pid_for "$cond")
    j0=$(jiffies "$pid")
    c0=$(cat $PS/charge_counter)
    t0=$(now_ms)
    plugged=0

    if [ "$work" = "traffic" ]; then
        bytes=$(( RATE * 1000000 / 8 * (MEASURE + 5) ))
        ( echo "$bytes $RATE"; sleep $(( MEASURE + 8 )) ) | nc -w 20 "$HOST" 18081 > /dev/null 2>&1 &
        trafficpid=$!
    fi

    i=0
    while [ $i -lt "$MEASURE" ]; do
        echo "$cond,$work,$rep,$(now_ms),$(cat $PS/current_now),$(cat $PS/voltage_now)" >> "$OUT"
        sleep 1
        i=$(( i + 1 ))
    done

    t1=$(now_ms)
    c1=$(cat $PS/charge_counter)
    j1=$(jiffies "$pid")
    [ -n "$trafficpid" ] && kill "$trafficpid" 2>/dev/null
    trafficpid=
    on_battery || plugged=1
    temp=$(cat $PS/temp)
    echo "$cond,$work,$rep,$t0,$t1,$c0,$c1,$j0,$j1,$tun,$plugged,$temp" >> "$RUNS"
    stop_all
    sleep 15
}

echo "cond,work,rep,ms,current_ua,voltage_uv" > "$OUT"
echo "cond,work,rep,t0_ms,t1_ms,charge0_uah,charge1_uah,jiffies0,jiffies1,tun,plugged,temp_decic" > "$RUNS"

# Nothing is measured until the cable is out
if [ "$DRY" = "dry" ]; then
    ORDERS="none_andronet_pcapdroid"
else
    echo "waiting for unplug"
    while ! on_battery; do sleep 2; done
    echo "on battery, starting in 20 s"
    sleep 20
    ORDERS="none_andronet_pcapdroid pcapdroid_none_andronet andronet_pcapdroid_none"
fi

rep=1
for orderline in $ORDERS; do
    order=$(echo "$orderline" | tr '_' ' ')
    for work in traffic idle; do
        for cond in $order; do
            echo "run rep=$rep $cond $work $(date)"
            run_one "$cond" "$work" "$rep"
        done
    done
    rep=$(( rep + 1 ))
done

stop_all
echo done > $D/energy_done
echo "finished $(date)"
