# The appliance pivot — from exploit target to a small, quiet home box

Once root is durable (see [DURABLE-ROOT.md](DURABLE-ROOT.md)), the box can be
repurposed: **keep the hardware, drop everything the vendor wanted it to be.**
This documents stripping it, replacing its launcher, and giving it jobs.

## 1. The hardware, measured

| | |
|---|---|
| SoC | Qualcomm **MSM8953**, 8× Cortex‑A53 @ 1.8 GHz |
| RAM | **2.95 GB** |
| Storage | 24 GB `/data` (≈ 21 GB free) |
| Screen | 800×1280 LCD |
| OS | Android 8.1.0, SELinux **permissive** (the payload clears enforcement) |
| Load | ~5 sustained (almost all of it vendor code — see §2) |

## 2. Strip (reversible, user‑space)

Two passes. Nothing flashed, no `/system` edits, every change has a one‑line
revert.

**Pass 1** — the two preinstalled app stores force‑stopped; window‑animation
scales set to 0; the OTA updater disabled:
`pm disable-user com.telefonica.movistarhome.updater` (revert `pm enable …`).

**Pass 2 — the hardware‑only pass: 20 packages disabled‑user**

- all 18 `com.telefonica.movistarhome.*`
- `com.movistarhome.control`
- `com.askey.tr069` (ISP management — **`:7547` stops answering**)
- `com.example.ck.socketservice` (factory priv‑app)
- the OTA updater (pass 1)

Plus Bluetooth off (`svc bluetooth disable`). Result: **0 vendor processes**,
threads **1589 → 1194**, and everything that matters still works — root worker,
agent, Termux, sshd, navbar, the launcher, the screen.

Revert: `pm enable <pkg>` / `svc bluetooth enable`.

## 3. `adb` — the door that does not exist

Four independent walls make `adb` impossible on this unit: the vendor binary cuts
the TCP path; `ctl.stop` is SELinux‑denied; init respawns it; and an `execve` of
either a script or an ELF inside an init‑namespace bind mount lands on `EACCES`.
It is parked (≈ 2‑3 % CPU, harmless). Iteration stays on the loopback-only `127.0.0.1:8080` `/cmd` (via ssh tunnel) +
`:8022` scp. See [reference/adbd-disabled.md](reference/adbd-disabled.md).

## 4. The launcher — from scratch

`com.mh.launcher`: a **framework‑only Java** app (no Gradle), built with
aapt2 + javac + d8 and signed with a stable local keystore. It enumerates
launchable apps through `PackageManager`, draws them in a grid on the 800×1280
panel, launches on tap, and shows clock + battery in a strip. Installed and set
as HOME with `cmd package set-home-activity`. The stock launcher
(`com.bearinmind.launcher314`) stays installed as a fallback.

Build/deploy: [appliance/](appliance/) — `./deploy.sh` builds, pushes, installs
and sets HOME in one command.

## 5. The clock — dead RTC, fixed from the network

The RTC is dead: **every boot the clock reads 1970**, and the stock NTP service
never syncs on its own. A wrong clock breaks TLS — which breaks the DNS filter's
encrypted upstreams and every log line.

Fix: read the **`Date:` header of a plain‑HTTP response** (no TLS needed) and set
the clock from it. On the box that is
[`tools/box/mh.sh`](appliance/tools/box/mh.sh) `time`; it is wired to run after
every boot by the **clock fixer** appended to `~/start.sh`:

```sh
if [ "$(date +%Y)" -lt 2024 ]; then
  setsid nohup bash -c '
    sleep 210                    # wait for the root door (BK chain is ~2.5 min)
    i=0
    while [ $i -lt 15 ]; do
      i=$((i+1))
      r=$(curl -s --max-time 25 -X POST --data-binary \
          "sh /data/local/tmp/mh/mh.sh boot" http://127.0.0.1:8080/cmd 2>/dev/null)
      case "$r" in *BOOT-OK*) echo "$(date) try=$i BOOT-OK" >> "$HOME/clockfix.log"; exit 0 ;; esac
      sleep 40
    done
  ' >>"$HOME/start.log" 2>&1 &
fi
```

`mh.sh boot` is idempotent — **time + pause the vendor loggers + start AdGuard
Home** — and prints `BOOT-OK` only when all three are ready. The `date +%Y` guard
means a later Termux session on an already‑fixed boot does nothing.

## 6. AdGuard Home — network‑wide DNS

AdGuard Home v0.107.79 runs from `/data/local/tmp/agh` **as root** (the
`u:r:shell:s0` context cannot bind port 53): **DNS on the box's LAN IPv4 `:53`**,
admin UI **localhost only** (`ssh -N -L 3000:127.0.0.1:3000 …` → `http://localhost:3000`).
It uses Termux's maintained CA bundle (Android 8.1's is too old for the DoH
upstreams) with plain‑IP bootstrap + fallback, so lookups keep working even when
the clock is wrong. It is started after every boot by the clock fixer.

Router DNS is **not** pointed at it yet — first: a DHCP reservation, and a check
of the router's IPv6 DNS advertisement (the filter is IPv4‑only).

## 7. Tools

| tool | what |
|---|---|
| `tools/box/mh.sh` | on the box: `boot` = time + loggers + adguard; also `time`, `loggers`, `agh` |
| `tools/settime.sh` | set the clock from the host in one command |
| `tools/cleanup.sh` | `apply\|revert\|status` — the disabled‑user strip |
| `tools/measure.sh` | record before/after numbers |
| `tools/adguard.sh` | `push\|start\|stop\|status\|log` for AdGuard Home |
| `tools/cycler.sh` | smart‑plug power‑cycle driver (dry by default, verifies plug state) |
| `deploy.sh` | build + push + install + set‑home the launcher |
| `device-tools/gsetns.c` | run a command inside init's mount namespace |
| `device-tools/adbd-pause.c` | the target for the adbd‑silence bind mount |

## 8. Possible extensions

- launcher polish: the grid should always start scrolled to the top;
- router DNS cutover, once the boot start is confirmed on the LAN;
- a dashboard home (weather / calendar / cards) and a Home Assistant panel
  (full HA does not fit this 32‑bit box).
