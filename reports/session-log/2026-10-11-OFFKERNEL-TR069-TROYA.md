# Off-kernel attack surface: Movistar Home TR069/Troya (JOB-100..110)

Date: 2026-10-11
Device: ASKEY RG3205W smart speaker, Android 8.1 armv7, kernel 3.18.71.
Reach: untrusted_app (uid 10042, Termux) + LAN control of the device + its ACS.

## Why this is the "nicest" path
No kernel bug / no race needed. Two SYSTEM apps are fully drivable from
untrusted_app, and the ROM is **test-keys** (public platform signing key).

## Confirmed primitives (all deterministic, no crash)
1. **Unprotected broadcast control of the SYSTEM TR069 app** (`/system/priv-app/AskeyTR69`,
   `sharedUserId="android.uid.system"`, `debuggable="true"`, `coreApp="true"`).
   Its `Receiver` registers (no permission) actions incl.:
   - `askey.tr069.intent.action.getcfg` → broadcasts the **entire config** as JSON
     (`com.askey.intent.action.userintf`). Verified: leaked `ManagementServer.URL/
     Username/Password`, `ConnectionRequestPassword`, CWMP `HttpsAcsCert`, TV/Aura JWTs.
   - `askey.tr069.intent.action.testurl` (extra `testurl`) → **sets the CWMP/ACS URL**.
     Verified: after delivering it, `ManagementServer.URL == http://<tester-host>:7014/…`
     (our Mac). ⇒ we own the managed ACS.
   - `askey.tr069.intent.action.setcfg` (extras `keyName`,`keyValue`) → **arbitrary config write as SYSTEM**.
   - `askey.socket.intent.action.aspsh` (extra `info`) → SYSTEM `commandProcess()`.
2. **ACS impersonation is easy**: `HttpsUtil`'s `checkServerTrusted()` is a **no-op**
   (accepts any cert) and `SSLSocketFactoryWrapper.getInsecure` exists; SOAP is parsed
   with a bare `new SAXBuilder()` (JDOM2) → XXE/privacy surface. We control DNS/ACS.
3. **The updater** (`com.telefonica.movistarhome.updater`, `sharedUserId="android.uid.system"`,
   perms **`INSTALL_PACKAGES`+`DELETE_PACKAGES`+`REBOOT`**) registers **unprotected dynamic
   broadcast receivers** (`UpdaterOperationsProxy`):
   - `…action.ACTION_UPDATE_APPS` → `updateApps()` → `getPackageAsFile("", Mode.APPS)` →
     downloads APKs from its backend and calls `AndroidComponent.silentInstallPackage(...)`
     = **silent install as SYSTEM**.
   - `…action.ACTION_UPDATE_FIRMWARE` (extra **`EXTRA_URL`**) → `updateFirmware(url)` —
     Mode.FIRMWARE goes to `RecoverySystem.installPackage` (recovery/flash); Mode.APPS installs APKs.
   - Exported `PackageService` (AIDL/`UpdaterOperations`) too.

## The one missing link
The updater's backend URL comes from **`/data/movistarhome/environments.json`**
(`TroyaUrlProvider` + `StorageProvider`: system app → `/data/movistarhome/`).
That dir is `0771 system:system` → **not writable by untrusted_app**. Candidates to
write it (all SYSTEM, being examined): `troya-config-service`
(`ConfigService` AIDL `IConfigService.getConfig`, exported `RefreshConfigurationService`,
`BootBroadcastReceiver`), which populate/push the environment config.

## Assessment vs the kernel paths
- **af_unix CVE-2021-0920**: race-gated, multi-day port.
- **CVE-2021-1905**: deterministic kernel primitive confirmed, UAF endgame elusive.
- **This (TR069/Troya)**: by far the most accessible — full control of two SYSTEM apps,
  ACS ownership, silent-install capability, test-keys ROM. Closest to a root/priv-esc
  chain; the remaining step is writing one config file (or reaching one config
  service) to redirect the updater backend to our server.

Artifacts: `tr069/` (AskeyTR69 decompiled), `troya/` (updater+auth decompiled),
`cfg/` (config-service decompiled), `socketsvc/` (8989 daemon); evidence uploads
20261011-2031..2036.

## Deep-dive results (JOB-111 + code)
- **MITM infra already present** from earlier sessions: `fake_acs.py` (7014/7016),
  `acs_http.py` (8020), dnsmasq hijacking `telefonica.net/movistar.*/rima-tde.net`.
- **Troya apps trust ANY TLS cert**: `backend/sdk/UnsafeOkHttpClientBuilder` uses a
  no-op `X509TrustManager` + always-true `HostnameVerifier` (updater AND config app).
- **Updater install modes (definitive)**:
  - `Mode.FIRMWARE` → `CandidatesUseCase.installFirmware` → `applyOTAAsync` →
    `RecoverySystem.installPackage` = **recovery OTA** (red-line / flashing).
  - `Mode.APPS` → `installCandidates` → `PackageManager.installPackage` →
    `AndroidComponent.silentInstallPackage` = **silent APK install as SYSTEM**.
    But APPS always fetches its manifest from the **backend** (no URL in the intent).
- **Backend URL** = `TroyaUrlProvider` → `/data/movistarhome/environments.json`
  (system app) else fallback `https://api.es-pro.movistar-home.com/api/`.
- **The wall**: `api.es-pro.movistar-home.com` is NOT covered by the dnsmasq
  hijack list, and reloading dnsmasq needs root (`kill -HUP`/`launchctl kickstart`
  → EPERM; `brew services` runs as user → no effect). So the device never resolves
  the Troya backend to us ⇒ can't drive the silent APK install. `/data/movistarhome`
  is `0771 system:system` (not writable). The exported SYSTEM `troya-config-service`
  (`ConfigService`/`IConfigService`, `RefreshConfigurationService`, `BootBroadcastReceiver`)
  writes environments.json but only from the (unreachable) backend.

## Net
Off-kernel gives: full SYSTEM-TR069 config read/write, ACS ownership (fake ACS live),
info leak (creds/JWTs), and a documented silent-install capability — but the final
step (control the updater backend) needs either a root-level DNS change on the Mac
(one `address=/movistar-home.com/<tester-host>` + dnsmasq reload) **or** writing
`/data/movistarhome/environments.json` as system. With that one change, the chain is:
`RefreshConfigurationService`/config-sync → `environments.json` → `ACTION_UPDATE_APPS`
→ updater `silentInstallPackage` → our test-key-signed `sharedUserId=system` APK.
