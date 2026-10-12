#!/usr/bin/env bash
# Cross-compile the arm32 harnesses (static, musl) with zig.
# Requires: zig (https://ziglang.org) on PATH.
set -euo pipefail
cd "$(dirname "$0")"

CC="${CC:-zig cc -target arm-linux-musleabihf}"
CFLAGS="-static -O2 -w -Wl,--strip-all"

for f in *.c; do
    out="${f%.c}"
    echo "[*] $f -> $out"
    # shellcheck disable=SC2086
    $CC $CFLAGS -o "$out" "$f"
    gzip -9 -c "$out" > "$out.gz"
done
echo "[+] done"
