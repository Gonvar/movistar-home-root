#!/bin/bash
# cycler.sh — unattended power-cycle driver for exploit iteration (host side).
#
# Watches the box's device posts (upload_server.log + uploads/) and, when a roll
# finishes or the box dies dark, cuts and restores power through a smart plug
# via two HomeKit shortcuts. Every plug action is verified by reading the plug
# state back; no blind toggles.
#
# Host-side HomeKit shortcuts this expects (names are examples):
#   "HM Plug State"  id <PLUG-STATE-SHORTCUT-ID> -> prints No | Yes
#   "ON / OFF HM"    id <PLUG-TOGGLE-SHORTCUT-ID> -> flips the plug
#   re-derive with: shortcuts list --show-identifiers
#
# Safety rules baked in:
#   R1  never cut while a roll is in flight (payload fetch / agent firing -> resolve)
#   R2  silence with any port open = possible silent win: never cut
#   R3  verify plug state around every action; abort on unknown state
#   R4  rate cap: >= MIN_GAP s between cuts, <= MAX_CUTS per run
#   R5  stop when BootKeeper is confirmed (leaves the box powered on)
#   R6  dry run by default (reads only); toggling requires --live
#
# Roll resolve signals:
#   termux chain : quiet >= QUIET s (the job's last post -- note the poller
#                  keeps polling /wait during runs, it is not a pause signal),
#                  or all ports dark for DARK_CONFIRM s (panic)
#   agent chain  : "AGENT mh-agent/4 RESULT" post
#   agent backoff: "backoff engaged" post -> GET :8080/run forces a fire
#                  (the agent allows one auto-retry, then locks itself)
#   alive+quiet  : door :8023 open = live win, hold; agent ctl up = hold;
#                  no door + no agent for LONG_HOLD = parked -> cycle
#   Auto-cycle gate after a normal resolve:
#     chain=agent or --expect-agent or --force-termux -> cycle
#     else (termux) -> log only; a human must open Termux after each boot
#
# Usage:
#   ./cycler.sh                          # observe only (dry run)
#   ./cycler.sh --live --force-termux    # cycle while a human still opens Termux
#   ./cycler.sh --live --expect-agent    # unattended (v4 agent fires every boot)
#   ./cycler.sh --stop-after 30          # self-test
set -u
cd "$(dirname "$0")" || exit 1

# ------------------------------- config ------------------------------------
LIVE=0; EXPECT_AGENT=0; FORCE_TERMUX=0; STOP_AFTER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --live)         LIVE=1 ;;
    --expect-agent) EXPECT_AGENT=1 ;;
    --force-termux) FORCE_TERMUX=1 ;;
    --stop-after)   STOP_AFTER="${2:?}"; shift ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
  shift
done

BOX=192.168.1.100
PORTS="8022 7547 8023 8080 8888 9999"   # 8023 = payload root door, 8080 = agent ctl (win tells)
SRV_LOG=upload_server.log
LOG=cycler.log
LOCK=.cycler.lock
STATE=.cycler.state
DONE_MARK=cycler.DONE

SH_BIN=$(command -v shortcuts || echo /usr/bin/shortcuts)
SH_STATE=<PLUG-STATE-SHORTCUT-ID>
SH_TOGGLE=<PLUG-TOGGLE-SHORTCUT-ID>

OFF_HOLD=15     # seconds the power stays off
QUIET=180       # seconds without device posts before resolve/panic checks
WAIT_FREE=45    # poller counts as free when a /wait line is younger than this
BOOT_WAIT=420   # seconds to wait for a boot signal after a restore
SETTLE=30       # seconds between roll resolve and the cycle decision
MIN_GAP=300     # minimum seconds between two cuts
MAX_CUTS=40     # hard cap per invocation
DARK_CONFIRM=60 # seconds a dark (all ports closed) box must stay dark
BK_PAT='__BK_DONE=0|package:com.mh.bootkeeper'

# agent-backoff recovery: after 2 consecutive deaths the agent refuses to fire
# on its own ("backoff engaged"); GET :8080/run clears it and fires one run.
# If /run fails for FORCE_STALL s, cut power (a fresh boot re-arms everything).
FORCE_GAP=45    # seconds between /run attempts
FORCE_MAX=6     # max /run attempts before the stall recovery cut
FORCE_STALL=300 # seconds after backoff with no fire -> recovery cut
PROBE_EVERY=60  # seconds between alive+quiet probes (door/status)
LONG_HOLD=900   # alive+quiet with no door/agent this long -> treat as parked
DOOR_PORT=8023

TMPD="${TMPDIR:-/tmp}/mh-cycler.$$"
mkdir -p "$TMPD"

# ------------------------------ helpers ------------------------------------
say(){ printf '[%s] %s\n' "$(date '+%F %T')" "$1" | tee -a "$LOG"; }
now(){ date +%s; }

run_sc(){ # $1=shortcut-id $2=out-file $3=timeout-s -> rc (124 on timeout)
  local id=$1 out=$2 t=$3 pid i rc
  rm -f "$out"
  ( "$SH_BIN" run "$id" --output-path "$out" >/dev/null 2>&1 ) &
  pid=$!
  i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i+1))
    if [ "$i" -ge "$t" ]; then
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      return 124
    fi
    sleep 1
  done
  wait "$pid"; rc=$?
  return "$rc"
}

plug_state(){ # prints No | Yes | unknown
  local out="$TMPD/state" s
  run_sc "$SH_STATE" "$out" 20 || true
  s=$(cat "$out" 2>/dev/null)
  case "$s" in
    No|no|Off|off|false|0) echo No ;;
    Yes|yes|On|on|true|1)  echo Yes ;;
    *)                     echo unknown ;;
  esac
}

plug_toggle(){
  [ "$LIVE" = 1 ] || { say "DRY: would toggle the plug"; return 0; }
  local rc
  run_sc "$SH_TOGGLE" "$TMPD/toggle" 30; rc=$?
  [ "$rc" = 0 ] || say "WARN: toggle rc=$rc"
  return 0
}

plug_want(){ # $1=No|Yes ; verify with reads, at most 3 rounds
  local want=$1 s i
  for i in 1 2 3; do
    s=$(plug_state)
    [ "$s" = "$want" ] && { say "plug ok: $s (round $i)"; return 0; }
    say "plug is \"$s\", want $want (round $i)"
    [ "$s" = unknown ] && { sleep 2; continue; }
    [ "$LIVE" = 1 ] || { say "DRY: not toggling"; return 0; }
    plug_toggle; sleep 3
  done
  s=$(plug_state)
  [ "$s" = "$want" ] && { say "plug ok: $s"; return 0; }
  say "PLUG FAIL: want $want, last \"$s\""
  return 1
}

ports_open(){ local p n=0; for p in $PORTS; do nc -z -w 2 "$BOX" "$p" >/dev/null 2>&1 && n=$((n+1)); done; echo "$n"; }

boot_signal(){ # $1 = termux | agent
  chain=$1; boot_seen=1; seq=$((seq+1)); phase=idle
  say "boot signal: $1 (seq $seq)"
  roll_open=0; resolved_ts=0; resolved_kind=""; handled=0
  dark_since=0; amb_since=0; agent_result=0; boot_deadline=0; boot_retry=0
  backoff_ts=0; force_ts=0; force_tries=0; no_door_since=0
}

classify(){ # $1 = uploaded file path
  local f=$1 head tail_
  head=$(head -c 400 "$f" 2>/dev/null)
  tail_=$(tail -c 400 "$f" 2>/dev/null)
  # MHBOT (BootKeeper -> Termux -> start.sh): fires once per Termux session and
  # is NOT a boot signal -- it reset a pending cycle and faked a new
  # boot.  The termux chain no longer fires (job.sh stubbed); agent posts are
  # the only boot signals now.
  case "$head" in *"service up (boot"*) boot_signal agent ;; esac
  case "$head" in *"firing at uptime"*) roll_open=1; phase=rolling; fire_ts=$t; backoff_ts=0; say "roll open: agent firing" ;; esac
  case "$head" in *"AGENT mh-agent"*"RESULT"*) roll_open=1; agent_result=1 ;; esac
  case "$head" in *"backoff engaged"*) backoff_ts=$t; force_ts=0; force_tries=0; say "backoff seen: will force /run" ;; esac
  case "$head" in *"no payload"*) say "WARNING: agent reports NO PAYLOAD -- check the server file" ;; esac
  # note: no "=== RUN" pattern here -- verdict-delivery posts replay the previous
  # run's trace and would fake a roll-open. The payload-fetch line and the agent
  # firing post are the precise signals.
  if printf '%s\n%s' "$head" "$tail_" | grep -qE "$BK_PAT"; then
    if [ "$bk_hit" = 0 ]; then say "BK marker seen in post: $f"; fi
    bk_hit=1
  fi
  if printf '%s\n%s' "$head" "$tail_" | grep -qE '__BK_DONE=[1-9]'; then
    if [ "$bk_fail_note" = 0 ]; then say "note: BK install rc!=0 seen (not confirmed)"; bk_fail_note=1; fi
  fi
}

do_cycle(){ # $1 = reason
  local why=$1
  say "cycle: $why"
  if ! plug_want No; then
    say "ABORT cycle: could not switch the plug off safely"
    return 1
  fi
  if [ "$LIVE" = 1 ]; then
    sleep "$OFF_HOLD"
  else
    say "DRY: would hold power off ${OFF_HOLD}s"
  fi
  if ! plug_want Yes; then
    say "RESTORE FAIL: retrying once"
    if ! plug_want Yes; then
      say "STOP: restore failed twice -- the plug may be OFF. CHECK MANUALLY."
      exit 3
    fi
  fi
  cuts=$((cuts+1)); last_cut=$t
  { echo "cuts=$cuts"; echo "last_cut=$last_cut"; } > "$STATE"
  say "cycle $cuts done (reason: $why)"
  if [ "$LIVE" = 1 ]; then
    phase=wait_boot; boot_deadline=$((t+BOOT_WAIT)); boot_seen=0
  fi
  return 0
}

# ------------------------------ start --------------------------------------
[ -f "$SRV_LOG" ] || { echo "no $SRV_LOG here"; exit 1; }
mkdir "$LOCK" 2>/dev/null || { echo "another cycler runs (stale? rm -rf $LOCK)"; exit 1; }
trap 'rm -rf "$LOCK" 2>/dev/null; rm -rf "$TMPD"' EXIT INT TERM
echo $$ > "$LOCK/pid"

LOG_SZ=$(stat -f%z "$SRV_LOG" 2>/dev/null || echo 0)
say "start: live=$LIVE expect_agent=$EXPECT_AGENT force_termux=$FORCE_TERMUX stop_after=${STOP_AFTER}s"
if [ -n "$(lsof -ti :8010 2>/dev/null)" ]; then
  say "upload server :8010 up (pid $(lsof -ti :8010 | head -1))"
else
  say "WARN: upload server :8010 not listening"
fi
say "plug state at start: $(plug_state)"

# state
phase=idle; chain=unknown
roll_open=0; resolved_ts=0; resolved_kind=""; handled=0
agent_result=0; bk_hit=0; bk_fail_note=0
seq=0; boot_seen=0; boot_deadline=0; boot_retry=0
dark_since=0; amb_since=0; fire_ts=0
backoff_ts=0; force_ts=0; force_tries=0; no_door_since=0; last_probe=0
cuts=0; last_cut=0
t=$(now); last_post_ts=$t; last_wait_ts=$t

# conservative bootstrap: a device post in the last 30 s means something may be in flight
newest=$(ls -t uploads/*.bin 2>/dev/null | head -1)
if [ -n "$newest" ]; then
  age=$(( t - $(stat -f%m "$newest") ))
  if [ "$age" -le 30 ]; then
    roll_open=1; phase=rolling
    say "note: device post ${age}s ago -- treating as in flight (no cuts until resolved)"
  fi
fi

START=$(now); last_beat=0

# ------------------------------ main loop ----------------------------------
while :; do
  t=$(now)
  if [ "$STOP_AFTER" -gt 0 ] && [ $((t-START)) -ge "$STOP_AFTER" ]; then say "stop-after reached"; break; fi

  # read new server-log lines
  cur=$(stat -f%z "$SRV_LOG" 2>/dev/null || echo 0)
  if [ "$cur" -lt "$LOG_SZ" ]; then LOG_SZ=0; fi
  if [ "$cur" -gt "$LOG_SZ" ]; then
    new=$(tail -c +$((LOG_SZ+1)) "$SRV_LOG" 2>/dev/null)
    LOG_SZ=$cur
    while IFS= read -r line; do
      case "$line" in
        *"req: GET /wait from $BOX"*) last_wait_ts=$t ;;
        *"req: GET /kgsl-forge-v3.gz from $BOX"*)
          roll_open=1; phase=rolling; last_fetch_ts=$t; last_post_ts=$t
          say "roll open: payload fetch" ;;
        *"req: GET /kgsl-forge.gz from $BOX"*)
          roll_open=1; phase=rolling; last_fetch_ts=$t; last_post_ts=$t
          say "roll open: agent payload fetch" ;;
        *"SAVED "*" -> "*)
          path=${line##*-> }
          last_post_ts=$t
          [ -f "$path" ] && classify "$path" ;;
      esac
    done <<< "$new"
  fi

  # BootKeeper stop condition
  if [ "$bk_hit" = 1 ]; then
    say "*** BOOTKEEPER CONFIRMED -- leaving power ON, stopping ***"
    date > "$DONE_MARK"
    break
  fi

  # roll resolution
  if [ "$roll_open" = 1 ] && [ "$resolved_ts" = 0 ]; then
    if [ "$chain" = agent ] && [ "$agent_result" = 1 ]; then
      resolved_ts=$t; resolved_kind=done; say "resolved: agent RESULT"
    else
      q=$((t - last_post_ts))
      if [ "$q" -ge "$QUIET" ]; then
        if [ "$chain" = termux ] && [ $((t - last_wait_ts)) -le "$WAIT_FREE" ]; then
          resolved_ts=$t; resolved_kind=done
          say "resolved: quiet ${q}s and poller free"
        else
          op=$(ports_open)
          if [ "$op" = 0 ]; then
            if [ "$dark_since" = 0 ]; then
              dark_since=$t
              say "quiet ${q}s, all ports dark (probe 1/2, no cut yet)"
            elif [ $((t - dark_since)) -ge "$DARK_CONFIRM" ]; then
              resolved_ts=$t; resolved_kind=panic
              say "resolved: dark box (panic) for $((t - dark_since))s"
            fi
          else
            if [ "$amb_since" = 0 ]; then
              amb_since=$t
              say "quiet ${q}s but $op port(s) open -- box alive, NOT cutting (rule R2)"
            fi
            # agent chain only: live win (door open) vs live agent (ctl up) vs
            # dead-app park (no door, no agent for LONG_HOLD -> safe to recycle)
            if [ "$chain" = agent ] && [ $((t - amb_since)) -ge 30 ] && [ $((t - last_probe)) -ge "$PROBE_EVERY" ]; then
              last_probe=$t
              if nc -z -w 2 "$BOX" "$DOOR_PORT" >/dev/null 2>&1; then
                no_door_since=0
                say "ALIVE+QUIET: root door :$DOOR_PORT OPEN -- possible LIVE WIN, holding"
              else
                st=$(curl -s --max-time 5 "http://127.0.0.1:8080/status" 2>/dev/null | tr '\n' ' ' | cut -c1-200)
                if [ -n "$st" ]; then
                  no_door_since=0
                  say "ALIVE+QUIET: agent up [$st]"
                else
                  if [ "$no_door_since" = 0 ]; then
                    no_door_since=$t
                    say "ALIVE+QUIET: no door, no agent -> watching (long hold)"
                  elif [ $((t - no_door_since)) -ge "$LONG_HOLD" ]; then
                    resolved_ts=$t; resolved_kind=done
                    say "resolved: alive but no door/agent for $((t-no_door_since))s -- parked"
                  fi
                fi
              fi
            fi
          fi
        fi
      fi
    fi
  fi

  # resolved -> decide
  if [ "$resolved_ts" != 0 ] && [ "$handled" = 0 ] && [ $((t - resolved_ts)) -ge "$SETTLE" ]; then
    handled=1
    can=0
    if [ "$resolved_kind" = panic ]; then
      can=1; why="panic recovery (box dark)"
    elif [ "$chain" = agent ] || [ "$EXPECT_AGENT" = 1 ] || [ "$FORCE_TERMUX" = 1 ]; then
      can=1; why="roll resolved (chain=$chain)"
    else
      why="termux chain: human opens Termux after reboot -- no auto-cycle"
    fi
    if [ "$can" = 1 ]; then
      if [ $((t - last_cut)) -lt "$MIN_GAP" ]; then
        say "cycle wanted ($why) but rate cap: <${MIN_GAP}s since last cut"
      elif [ "$cuts" -ge "$MAX_CUTS" ]; then
        say "STOP: MAX_CUTS ($MAX_CUTS) reached"; break
      else
        do_cycle "$why"
      fi
    else
      say "no action: $why"
    fi
  fi

  # agent backoff -> force /run (the agent allows one auto-retry, then locks
  # itself; GET :8080/run clears the backoff and fires one run now)
  if [ "$backoff_ts" != 0 ] && [ "$roll_open" = 0 ]; then
    if [ $((t - force_ts)) -ge "$FORCE_GAP" ]; then
      if [ "$force_tries" -lt "$FORCE_MAX" ]; then
        force_tries=$((force_tries+1)); force_ts=$t
        if [ "$LIVE" = 1 ]; then
          code=$(curl -s --max-time 5 -o "$TMPD/run.out" -w '%{http_code}' "http://127.0.0.1:8080/run" 2>/dev/null || echo 000)
          say "force /run -> http $code (try $force_tries/$FORCE_MAX)"
        else
          say "DRY: would force /run (try $force_tries/$FORCE_MAX)"
        fi
      elif [ $((t - backoff_ts)) -ge "$FORCE_STALL" ]; then
        if [ $((t - last_cut)) -ge "$MIN_GAP" ]; then
          backoff_ts=0
          do_cycle "backoff stall: agent declined and /run did not fire"
        else
          say "backoff stall: rate cap holds the cut"
        fi
      fi
    fi
  fi

  # wait_boot phase (live only)
  if [ "$phase" = wait_boot ] && [ "$LIVE" = 1 ]; then
    if [ "$boot_seen" = 1 ]; then
      phase=idle; say "boot after cycle confirmed"
    elif [ "$t" -ge "$boot_deadline" ]; then
      if [ "$EXPECT_AGENT" = 1 ] && [ "$boot_retry" -lt 1 ]; then
        boot_retry=1
        say "no boot signal after ${BOOT_WAIT}s -- retrying cycle"
        last_cut=$(( t - MIN_GAP ))
        do_cycle "boot retry"
      else
        say "STOP: no boot signal after restore -- check plug and box manually"
        break
      fi
    fi
  fi

  # heartbeat every 60 s
  if [ $((t - last_beat)) -ge 60 ]; then
    last_beat=$t
    say "idle: phase=$phase chain=$chain roll_open=$roll_open last_post=$((t-last_post_ts))s last_wait=$((t-last_wait_ts))s cuts=$cuts"
  fi

  sleep 2
done
say "exit"
