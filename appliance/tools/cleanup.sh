#!/bin/bash
# Turn off stock bloat on the box. Everything here is reversible.
#   tools/cleanup.sh apply    pause Askey loggers (until reboot) + disable unused apps
#   tools/cleanup.sh revert   resume the loggers + re-enable the apps
#   tools/cleanup.sh status   show logger + app state
#
# Never touched: com.mh.agent (root door, :8080), com.termux (sshd, :8022),
# com.mh.helper, com.mh.bootkeeper, com.mh.navbar, defcontainer/packageinstaller
# (pm install needs them), keyboard, webview, providers, systemui, settings,
# phone/telephony.
set -euo pipefail

DOOR="http://127.0.0.1:8080/cmd"
door() { curl -s --max-time 60 -X POST --data-binary "$1" "$DOOR"; }

# Askey firmware loggers (init services askey_*logd): askey_packetlogd is
# tcpdump capturing all traffic, the other five are logcat writers.

# Stock apps with no use on this box.
APPS_A="com.android.email com.android.exchange com.android.mms com.android.music com.caf.fmradio com.android.soundrecorder com.android.quicksearchbox"
APPS_B="com.android.protips com.qualcomm.qti.logkit com.qualcomm.qti.qcom_accesslogkit com.qualcomm.qti.qmmi com.qualcomm.embms com.dsi.ant.server com.smartiotlabs.iotbridge.service"

SH='echo u:r:shell:s0 > /proc/self/attr/current;'

# The door's SELinux context can't use ctl.stop, and init respawns killed
# loggers, so they're paused with SIGSTOP instead (init doesn't respawn a
# stopped process). Undo: revert, or a reboot. Targets: tcpdump + the logcat
# processes whose parent is init (pid 1).
FREEZE='for p in $(pidof tcpdump) $(for d in /proc/[0-9]*; do [ "$(cat $d/comm 2>/dev/null)" = logcat ] && grep -q "^PPid:[[:space:]]*1$" $d/status && echo ${d#/proc/}; done); do kill -'
SHOWLOG='for d in /proc/[0-9]*; do c=$(cat $d/comm 2>/dev/null); case $c in tcpdump|logcat) echo "$c ${d#/proc/} $(grep ^State: $d/status)";; esac; done'

case "${1:-status}" in
    apply)
        door "${FREEZE}STOP \$p; done; $SHOWLOG"
        # chunks keep each door call well under its 30 s limit
        for chunk in "$APPS_A" "$APPS_B"; do
            door "$SH for p in $chunk; do am force-stop \$p; pm disable-user --user 0 \$p; done"
        done
        ;;
    revert)
        door "${FREEZE}CONT \$p; done; $SHOWLOG"
        for chunk in "$APPS_A" "$APPS_B"; do
            door "$SH for p in $chunk; do pm enable --user 0 \$p; done"
        done
        ;;
    status)
        door "$SHOWLOG; $SH pm list packages -d | sed s/package:// | sort"
        ;;
    *) echo "usage: $0 apply|revert|status" >&2; exit 1;;
esac
