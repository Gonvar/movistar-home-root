#!/system/bin/sh
# Box-side helper, lives at /data/local/tmp/mh/mh.sh (pushed by hand via the door).
# Runs as root through the door, in the door's plain root context (the
# u:r:shell:s0 context can't bind port 53, so don't switch for agh).
#
#   sh /data/local/tmp/mh/mh.sh boot      time + loggers + agh
#   sh /data/local/tmp/mh/mh.sh time|loggers|agh
#
# ~/start.sh's clock fixer runs "boot" after every reboot (once the root door
# is up) and retries until it prints BOOT-OK (BOOT-WAIT = something not ready
# yet, e.g. Wi-Fi). Every step is idempotent. Keep a run under ~20 s (door
# limit). Log: $MH/boot.log
MH=/data/local/tmp/mh
AGH=/data/local/tmp/agh
LAN_IP=192.168.1.100
TX=/data/data/com.termux/files/usr
LOG=$MH/boot.log

log() { echo "$(date '+%F %T') $*" >> $LOG; echo "$*"; }

# "Date:" header of a plain-HTTP response: no TLS, so it works with a 1970 clock
http_date() {
    u=connectivitycheck.gstatic.com
    d=$(LD_LIBRARY_PATH=$TX/lib $TX/bin/curl -sI --max-time 5 http://$u/generate_204 2>/dev/null | grep -i '^date:')
    [ -z "$d" ] && d=$(printf 'HEAD /generate_204 HTTP/1.0\r\nHost: %s\r\n\r\n' $u \
        | toybox timeout 5 toybox nc $u 80 2>/dev/null | grep -i '^date:')
    echo "$d" | tr -d '\r'
}

# RTC is dead and the Askey NTP service doesn't sync, so set it from HTTP Date
do_time() {
    [ "$(date +%Y)" -ge 2024 ] && { log "time ok: $(date)"; return 0; }
    set -- $(http_date)    # Date: Sun, 18 Oct 2026 17:13:42 GMT
    [ "$#" -ge 6 ] || { log "time: no Date header yet"; return 1; }
    case $4 in
        Jan) m=01;; Feb) m=02;; Mar) m=03;; Apr) m=04;; May) m=05;; Jun) m=06;;
        Jul) m=07;; Aug) m=08;; Sep) m=09;; Oct) m=10;; Nov) m=11;; Dec) m=12;;
        *) log "time: bad month '$4'"; return 1;;
    esac
    d=$3; [ ${#d} -eq 1 ] && d=0$d
    hms=$6; h=${hms%%:*}; r=${hms#*:}; mi=${r%%:*}; s=${r#*:}
    toybox date -u $m$d$h$mi$5.$s >/dev/null || { log "time: date failed"; return 1; }
    log "time set: $(date)"
}

# Askey loggers: tcpdump (all traffic) + the logcat writers started by init.
# ctl.stop is denied by SELinux and init respawns killed ones, so pause them.
do_loggers() {
    n=0
    for p in $(pidof tcpdump) $(for d in /proc/[0-9]*; do
            [ "$(cat $d/comm 2>/dev/null)" = logcat ] \
                && grep -q "^PPid:[[:space:]]*1$" $d/status && echo ${d#/proc/}; done); do
        kill -STOP $p && n=$((n + 1))
    done
    log "loggers paused: $n"
}

# AdGuard Home: DNS on the LAN IPv4 only, admin UI on localhost only
do_agh() {
    p=$(cat $AGH/agh.pid 2>/dev/null)
    if [ -n "$p" ] && [ -d /proc/$p ] && grep -q AdGuardHome /proc/$p/cmdline; then
        log "agh running: pid $p"; return 0
    fi
    ip -4 addr show wlan0 2>/dev/null | grep -q "inet $LAN_IP/" \
        || { log "agh: wlan0 doesn't have $LAN_IP yet"; return 1; }
    cd $AGH || return 1
    # Android 8.1's CA store is too old for the DoH upstreams; use Termux's
    cp $TX/etc/tls/cert.pem $AGH/cacert.pem 2>/dev/null; chmod 600 $AGH/cacert.pem
    SSL_CERT_FILE=$AGH/cacert.pem setsid ./AdGuardHome -w $AGH -c $AGH/AdGuardHome.yaml \
        --web-addr 127.0.0.1:3000 --no-check-update -l $AGH/agh.log --pidfile $AGH/agh.pid \
        </dev/null >/dev/null 2>&1 &
    sleep 3
    p=$(cat $AGH/agh.pid 2>/dev/null)
    [ -n "$p" ] && [ -d /proc/$p ] || { log "agh: failed to start"; return 1; }
    # leave the door app's process group (Android kills an app's whole group)
    # and keep the low-memory killer away from it
    echo $p > /acct/cgroup.procs
    echo -800 > /proc/$p/oom_score_adj
    log "agh started: pid $p"
}

mkdir -p $MH
case "$1" in
    boot)
        log "boot run"
        ok=1
        do_time || ok=0
        do_loggers
        do_agh || ok=0
        [ $ok = 1 ] && log BOOT-OK || log BOOT-WAIT
        ;;
    time) do_time ;;
    loggers) do_loggers ;;
    agh) do_agh ;;
    *) echo "usage: mh.sh boot|time|loggers|agh"; exit 1 ;;
esac
