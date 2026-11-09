#!/system/bin/sh
# Stand-in for a root manager's su on the test emulator only.
#
# Android forks apps with an empty capability bounding set, so a setuid binary started by an app
# can never regain CAP_NET_RAW. Real root managers solve this with a daemon started by init, and
# so does this: scripts/rooted_experiment.py runs a root listener on 127.0.0.1:5999 that executes
# the command it is handed and connects its stdio to the socket.
case "$2" in
  id) echo "uid=0(root) gid=0(root) groups=0(root)"; exit 0 ;;
esac
{ printf '%s\n' "$2"; cat; } | exec nc 127.0.0.1 5999
