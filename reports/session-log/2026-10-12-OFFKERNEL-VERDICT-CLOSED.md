# VERDICT — off-kernel silent-install chain: CLOSED (two fatal flaws, receipts)
Date: 2026-10-12 ~11:05. Supersedes CHECKPOINT-V2 and the "one power-cycle away" claim.

## The chain is dead — twice over

### Fatal flaw 1: the updater validates TLS (no MITM transport)
`updater-src/.../di/module/AppModule.provideOkHttpClient()` = **stock
`OkHttpClient.Builder()`** — no custom trust manager, no hostname verifier.
`UnsafeOkHttpClientBuilder` exists in the shared SDK but is used **only by
`HomeZoneApiClient`** (checked in both updater-src and cfg). The 0.588.0 live
updater keeps this (Kotlin refactor, AppModule unchanged).

⇒ Our self-signed `fake_troya.py` can never serve the updater. It explains
every "resolve-then-silence" signature we saw (10:39:00 today: A+AAAA resolve
→ TLS rejected → silent abort, zero HTTP requests), and it means yesterday's
"device reached the backend" evidence was **only our own `curl -k` tests**.
No cleartext escape either: neither 0.561 nor 0.588 manifests set
`usesCleartextTraffic`, and targetSdk 28 blocks cleartext by default.

### Fatal flaw 2: the platform key is ASKEY's private cert, not the AOSP testkey
Signing certs extracted from the LIVE pulled APKs (`loot/installed-updater-20261012/base.apk`)
and system images — all platform apps (AskeyTR69, updater, auth) are signed:

    subject=C=TW,...,CN=Askey, emailAddress=anderson_yang@askey.com
    sha256 79:C6:3B:DF:78:57:18:B9:CC:55:63:6D:B1:B5:64:61:46:74:74:55:1F:A3:E6:72:2F:31:EA:31:9F:B6:67:27

Our staged `troya/pwn.apk` is signed with the **public AOSP testkey**
(`keys/platform.*`, `CN=Android`, sha256 C8:A2:...:B8) — a different key.

⇒ A `sharedUserId="android.uid.system"` APK signed by us is **rejected at
install** (PMS signature-merge check against existing uid-1000 members).
Even with perfect transport, nothing we build can become uid 1000.

Both facts were already established in `reports/2026-10-11-sol-handoff.md` §2e/§2f
(written yesterday midday) — and the later ACS-DNS checkpoint (21:13) that
re-launched this chain ("Troya apps trust ANY cert", "platform key obtained")
relied on assumptions that handoff had already refuted. The chain was built on
those unchecked assumptions. Process lesson recorded.

## What survives from tonight (keep)

- **Clock control**: SNTP (sudo, abs mode) working; device clock now correct.
  The clock-control primitive (sol §1) remains a real, proven capability.
- **Updater 0.588.0 decompile**: `/tmp/ups` (0.561, system image) and `/tmp/up588`
  (0.588, live-pulled). Key facts: `PackageService.onBind` → null (no AIDL);
  dynamic receiver registered with `registerReceiver(rx, filter, "", null)`
  ⇒ **sender must be uid 0/1000** (checkComponentPermission bypass); daily
  self-alarm (PendingIntent as uid 1000) only fires if the process is alive;
  `semantic_version` bundle requirement (REA, verified) is real but moot.
- **Payload build pipeline**: javac(bootclasspath android.jar from
  /tmp/plat28) → d8 → apktool b (raw dex) → openssl pkcs12 → jarsigner v1.
  Reusable for any future payload that does NOT need uid 1000.
- **Broadcast-permission mechanics**: only uid 0/1000 senders reach the
  updater's receivers; Termux broadcasts are silently dropped (result=0 lies).
- Visibility on 8.1 from untrusted: `ps`/`dumpsys`/`logcat(other uids)` all
  fenced; `logcat` shows own uid only; /proc/stat processes line hidden.
- DNS/NTP/ACS infra all healthy; `job.sh` reverted to idle.

## Where root must come from now (standing conclusion, re-confirmed)

The app layer is closed (uid 1000 needs the ASKEY key; uid 2000 is
seapp-gated dead per sol-handoff §2; signature perms need the ASKEY key).
**Kernel LPE is the only remaining path.** Priority order:

1. **CVE-2021-0920 (af_unix GC vs MSG_PEEK)** — race CONFIRMED HOT on target
   (small-`pre` sweep panicked the device). The endgame needs: measure GC
   window, widen with thousands of α nodes, controlled `scm_fp_list` reclaim
   so a win leaks instead of panicking. Harness + safe oracle exist
   (`binder-exploit/unix-gpz5.c`, reports + handoff from 2026-10-11).
2. **CVE-2021-1905 (KGSL pid-reuse)** — deterministic primitive confirmed
   (JOB-97); endgame (stale SMMU PTEs) hard but documented.
3. **CVE-2019-2215** — read-only arb read (write family closed by the
   usercopy wall) — valuable as an ORACLE for (1)/(2).
4. KGSL SVM wrap-around (`7a4e12ab` guard absent) — unaudited alternate.

The af_unix port resumes from `reports/2026-10-11-AF_UNIX-0920-GPZ-HANDOFF.md`,
with the safety order: reclaim first, race second. Do not run bare small-`pre`
sweeps again (device down ~15 min each).
