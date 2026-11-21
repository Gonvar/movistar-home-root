#!/bin/bash
# Set the box clock from this Mac (box RTC is dead -> 1970 after every reboot,
# and the Askey-patched NTP service doesn't sync on its own).
set -euo pipefail
T=$(date -u +%m%d%H%M%Y.%S)
curl -s --max-time 20 -X POST --data-binary "toybox date -u $T >/dev/null; date" \
    http://127.0.0.1:8080/cmd
echo "mac: $(date)"
