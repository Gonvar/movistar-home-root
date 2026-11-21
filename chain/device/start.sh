#!/data/data/com.termux/files/usr/bin/sh
# One idempotent bring-up for the Movistar Home toolkit: sshd (+ keeper) and the
# job poller, then a heartbeat POST.
#
# It is called automatically by ~/.bashrc on every fresh Termux session, so after
# a power cycle the only manual action is opening the Termux app.  Running it by
# hand (`sh ~/start.sh`) is always safe and always does the same thing.
#
# Why a heartbeat: it tells the Mac-side auto-armer, from the server side, that a
# fresh boot is up -- no ssh and no human timing needed to arm the exploit.
H=/data/data/com.termux/files/home
PREFIX=/data/data/com.termux/files/usr
SRV=${MH_SRV:-http://192.168.1.101:8010}
LOG=$H/start.log
up(){ echo $(( $(awk '{print $22}' /proc/self/stat 2>/dev/null || echo 0) / 100 )); }
# Liveness of the sshd LISTENER = "can I connect to :8022".
# Neither pgrep form is usable on this box: `pgrep -x sshd` reports no match even
# though a process with comm=sshd is listening, and `pgrep -f sshd` also matches
# this keeper's own command line (so it would claim sshd is up while it is dead).
# /dev/tcp is a bash feature and /bin/sh here is dash, hence the explicit bash.
listen(){ bash -c '(exec 3<>/dev/tcp/127.0.0.1/8022) 2>/dev/null'; }
echo "$(date) start.sh uptime=$(up)s sshd=$(listen && echo up || echo down)" >> "$LOG"

# sshd on :8022.  A second instance simply fails to bind, which is harmless, so no
# guard is needed.  (Do NOT pkill sshd here: that would drop the operator's own
# session.)
"$PREFIX/bin/sshd" 2>>"$LOG"

# keeper: bring the listener back within 15 s if it ever dies (pid-guarded)
K=$(cat "$H/.keeper.pid" 2>/dev/null || echo 0); case "$K" in ''|*[!0-9]*) K=0;; esac
# kill -0 alone is not enough: after a reboot a recycled PID can make a dead
# keeper look alive (same trap that silently blocked a draw).
if [ "$K" = 0 ] || ! kill -0 "$K" 2>/dev/null || ! tr '\0' ' ' <"/proc/$K/cmdline" 2>/dev/null | grep -q sshd; then
  setsid nohup bash -c 'while true; do (exec 3<>/dev/tcp/127.0.0.1/8022) 2>/dev/null || /data/data/com.termux/files/usr/bin/sshd; sleep 15; done' >>"$LOG" 2>&1 &
  echo $! > "$H/.keeper.pid"
  echo "keeper started pid=$!" >> "$LOG"
fi

# the job poller: exactly one, tracked by $H/.poller.pid (poller.sh writes it)
P=$(cat "$H/.poller.pid" 2>/dev/null || echo 0); case "$P" in ''|*[!0-9]*) P=0;; esac
# same recycled-PID trap (a transient process sat on the
# stale pid and this guard silently skipped the poller for the whole boot).
# Only a pid whose cmdline is really poller.sh counts as the live poller.
if [ "$P" = 0 ] || ! kill -0 "$P" 2>/dev/null || ! tr '\0' ' ' <"/proc/$P/cmdline" 2>/dev/null | grep -q poller.sh; then
  setsid nohup bash "$H/poller.sh" >> "$H/poller.log" 2>&1 &
  echo "poller launched (stale pid=$P)" >> "$LOG"
fi

# heartbeat -> the auto-armer on the Mac.  "MHBOT" = a session started the stack.
curl -s --max-time 5 -X POST --data-binary \
  "MHBOT uptime=$(up)s sshd=$(listen && echo up || echo down) poller=$(cat "$H/.poller.pid" 2>/dev/null)" \
  "$SRV/" >/dev/null 2>&1

# clock fixer: this box has no working RTC (clock reads 1970 after every boot)
# and the stock NTP service never syncs on its own.  Once the root door is up
# (~2.5-3 min after boot: BootKeeper -> Termux -> agent chain), ask it to set
# the clock, pause the Askey loggers and start AdGuard -- `sh /data/local/tmp/
# mh/mh.sh boot` is idempotent and prints BOOT-OK when all three are ready.
# The first attempt waits t+210 s so the boot chain's BootKeeper round is never
# clobbered; then it retries every 40 s (15 tries max).  Results land in
# ~/clockfix.log.  No-op when the clock is already set (e.g. a later Termux
# session on the same boot).
if [ "$(date +%Y)" -lt 2024 ]; then
  setsid nohup bash -c '
    sleep 210
    i=0
    while [ $i -lt 15 ]; do
      i=$((i+1))
      r=$(curl -s --max-time 25 -X POST --data-binary \
          "sh /data/local/tmp/mh/mh.sh boot" http://127.0.0.1:8080/cmd 2>/dev/null)
      case "$r" in
        *BOOT-OK*) echo "$(date) try=$i BOOT-OK" >> "$HOME/clockfix.log"; exit 0 ;;
      esac
      echo "$(date) try=$i: $(printf %s "$r" | tail -n 1)" >> "$HOME/clockfix.log"
      sleep 40
    done
    echo "$(date) gave up after 15 tries" >> "$HOME/clockfix.log"
  ' >>"$LOG" 2>&1 &
fi
exit 0
