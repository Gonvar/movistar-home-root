#!/data/data/com.termux/files/usr/bin/bash
# poller v3 - long-poll job runner.
#  * GET /wait holds the connection until job.sh changes -> near-instant delivery
#  * one job at a time, hard 300s timeout, new push preempts a running job
HOST="http://192.168.1.100:8010"
LAST="$HOME/.poller-last"; touch "$LAST"
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock 2>/dev/null
echo "poller v3 (long-poll) started $(date)"
JOBPID=""
while true; do
  CODE=$(curl -s -o "$HOME/job.sh" -w "%{http_code}" --max-time 40 "$HOST/wait" 2>/dev/null)
  if [ "$CODE" = "200" ] && ! cmp -s "$HOME/job.sh" "$LAST" 2>/dev/null; then
    cp "$HOME/job.sh" "$LAST"
    head -1 "$HOME/job.sh" | grep -q POLLER-STOP && break
    if [ -n "$JOBPID" ] && kill -0 "$JOBPID" 2>/dev/null; then
      pkill -9 -f kgsl-forge 2>/dev/null          # cut a hung attempt short
      kill -9 "$JOBPID" 2>/dev/null
    fi
    echo "[v3] run $(date)"
    ( timeout -s TERM -k 15 300 bash "$HOME/job.sh" > "$HOME/jobout.txt" 2>&1
      curl -s --max-time 20 -X POST --data-binary @"$HOME/jobout.txt" "$HOST/" 2>/dev/null
      echo "[v3] done $(date)" ) &
    JOBPID=$!
  fi
done
