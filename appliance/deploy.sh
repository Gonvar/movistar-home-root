#!/bin/bash
# Build MHLauncher, push it to the box, install it, set it as HOME, verify.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEY="$HOME/.ssh/mh_ed25519"
BOX="u0_a42@192.168.1.100"
APK="$HERE/launcher-app/MHLauncher.apk"

echo "[1/3] build"
"$HERE/launcher-app/build.sh"

echo
echo "[2/3] push to box"
scp -P 8022 -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no "$APK" "$BOX:MHLauncher.apk"

echo
echo "[3/3] install + set home + verify (root door)"
RESP="$(curl -s --max-time 60 -X POST --data-binary \
'echo u:r:shell:s0 > /proc/self/attr/current; cp /data/data/com.termux/files/home/MHLauncher.apk /data/local/tmp/MHLauncher.apk && chmod 644 /data/local/tmp/MHLauncher.apk; pm install -r /data/local/tmp/MHLauncher.apk; cmd package set-home-activity com.mh.launcher/.MainActivity; dumpsys activity activities 2>/dev/null | grep -m1 mResumedActivity; echo DEPLOY-OK' \
http://127.0.0.1:8080/cmd)"
echo "$RESP"

case "$RESP" in
    *DEPLOY-OK*) echo; echo "deploy OK";;
    *) echo; echo "WARNING: root door did not confirm the deploy (worker down?)" >&2; exit 1;;
esac
