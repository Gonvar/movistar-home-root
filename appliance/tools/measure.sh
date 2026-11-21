#!/bin/bash
# Snapshot of how busy the box is: idle flash writes, memory, process count,
# cold launch times. Read-only (apart from launching and closing a few apps).
# Usage: tools/measure.sh [label]   -> prints and appends to tools/measurements.log
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DOOR="http://127.0.0.1:8080/cmd"
LABEL="${1:-snapshot}"

door() { curl -s --max-time 60 -X POST --data-binary "$1" "$DOOR"; }

# 1) idle: flash sectors written over 15 s, memory, processes
IDLE="$(door 'S=15; a=$(grep " mmcblk0 " /proc/diskstats); sleep $S; b=$(grep " mmcblk0 " /proc/diskstats); echo "DISK_A $a"; echo "DISK_B $b"; echo "SECS $S"; grep MemAvailable /proc/meminfo; echo "PROCS $(ps -A | wc -l)"; cat /proc/loadavg')"

# 2) cold launch times (each app force-stopped first), back to home after
APPS="com.android.settings com.android.calendar com.android.deskclock"
LAUNCH="$(door "echo u:r:shell:s0 > /proc/self/attr/current; for p in $APPS; do c=\$(cmd package resolve-activity --brief -c android.intent.category.LAUNCHER \$p | tail -1); for r in 1 2; do t=\$(am start -W -S -n \$c | grep TotalTime); echo \"LAUNCH \$p \$t\"; input keyevent 3; sleep 0.5; done; done")"

python3 - "$LABEL" "$IDLE" "$LAUNCH" <<'EOF' | tee -a "$HERE/measurements.log"
import sys, re
label, idle, launch = sys.argv[1:4]
a = re.search(r"DISK_A\s+(.*)", idle).group(1).split()
b = re.search(r"DISK_B\s+(.*)", idle).group(1).split()
secs = int(re.search(r"SECS (\d+)", idle).group(1))
# diskstats: major minor name reads ... field index 9 = sectors written
kb_s = (int(b[9]) - int(a[9])) * 512 / 1024 / secs
mem = int(re.search(r"MemAvailable:\s+(\d+)", idle).group(1)) // 1024
procs = re.search(r"PROCS\s+(\d+)", idle).group(1)
load = re.search(r"^([\d.]+ [\d.]+ [\d.]+)", idle, re.M).group(1)
times = {}
for m in re.finditer(r"LAUNCH (\S+) TotalTime: (\d+)", launch):
    times.setdefault(m.group(1).split(".")[-1], []).append(int(m.group(2)))
print(f"== {label}")
print(f"  idle flash writes : {kb_s:.1f} KB/s")
print(f"  MemAvailable      : {mem} MB")
print(f"  processes         : {procs}")
print(f"  loadavg           : {load}")
for k, v in times.items():
    print(f"  cold launch {k:<9}: {' / '.join(map(str, v))} ms")
EOF
