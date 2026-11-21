#!/bin/bash
# AdGuard Home (network-wide ad blocking DNS) on the box.
#   tools/adguard.sh push|start|stop|status|log
#   push: copy tools/adguard/AdGuardHome.yaml to the box (stop it first).
#         WARNING: overwrites the live config, so anything changed in the
#         admin UI since (filters, settings) is lost. Only for first setup.
#
# Lives in /data/local/tmp/agh (binary, AdGuardHome.yaml, data/, agh.log).
# Runs as root from the door's plain root context: the u:r:shell:s0 context
# can't bind port 53. Everything binds to the LAN IPv4 only (the box also has
# public IPv6 addresses): DNS 192.168.1.100:53. Admin UI is localhost-only
# with no login - open it through ssh -N -L 3000:127.0.0.1:3000 mhbox.
# Not started at boot yet: after a reboot, run tools/settime.sh then start.
set -euo pipefail

DOOR="http://127.0.0.1:8080/cmd"
door() { curl -s --max-time 60 -X POST --data-binary "$1" "$DOOR"; }

DIR=/data/local/tmp/agh
PIDOF="p=\$(cat $DIR/agh.pid 2>/dev/null); [ -n \"\$p\" ] && [ -d /proc/\$p ] && grep -q AdGuardHome /proc/\$p/cmdline"

case "${1:-status}" in
    start)
        door "if $PIDOF; then echo already running pid \$p; exit 0; fi
cd $DIR
# Android 8.1's CA store is from 2018 (no Cloudflare root etc.); use Termux's
# maintained bundle, copied in so a missing Termux file doesn't break DNS
cp /data/data/com.termux/files/usr/etc/tls/cert.pem $DIR/cacert.pem 2>/dev/null; chmod 600 $DIR/cacert.pem
SSL_CERT_FILE=$DIR/cacert.pem setsid ./AdGuardHome -w $DIR -c $DIR/AdGuardHome.yaml \
  --web-addr 127.0.0.1:3000 --no-check-update -l $DIR/agh.log --pidfile $DIR/agh.pid \
  </dev/null >/dev/null 2>&1 &
sleep 3
p=\$(cat $DIR/agh.pid 2>/dev/null || pidof AdGuardHome)
# leave the door app's process group (Android kills an app's whole group) and
# keep the low-memory killer away from it
echo \$p > /acct/cgroup.procs
echo -800 > /proc/\$p/oom_score_adj
echo pid \$p; cat /proc/\$p/cgroup | grep -E 'cpuacct|^[0-9]+::'; echo oom_adj \$(cat /proc/\$p/oom_score_adj)"
        ;;
    push)
        HERE="$(cd "$(dirname "$0")" && pwd)"
        scp -q -P 8022 -i ~/.ssh/mh_ed25519 "$HERE/adguard/AdGuardHome.yaml" u0_a42@192.168.1.100:AdGuardHome.yaml
        door "if $PIDOF; then echo 'running - stop it first'; exit 1; fi
cp /data/data/com.termux/files/home/AdGuardHome.yaml $DIR/AdGuardHome.yaml && rm /data/data/com.termux/files/home/AdGuardHome.yaml
chmod 700 $DIR; chmod 600 $DIR/AdGuardHome.yaml
$DIR/AdGuardHome -w $DIR -c $DIR/AdGuardHome.yaml --check-config 2>&1 | tail -3"
        ;;
    stop)
        door "if $PIDOF; then kill \$p; sleep 2; echo stopped \$p; else echo not running; fi"
        ;;
    status)
        door "if $PIDOF; then echo running pid \$p rss=\$(grep VmRSS /proc/\$p/status); cat /proc/\$p/cgroup | grep cpuacct; else echo not running; fi; grep -E ':0035 |:0BB8 ' /proc/net/udp /proc/net/tcp | cut -c1-60"
        ;;
    log)
        door "tail -25 $DIR/agh.log"
        ;;
    *) echo "usage: $0 start|stop|status|log" >&2; exit 1;;
esac
