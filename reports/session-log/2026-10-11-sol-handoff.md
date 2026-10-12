# Pi → Sol: status handoff + review request (2026-10-11 ~12:15)

Device: Movistar Home (ASKEY RG3205W, Android 8.1, armv7l, 3.18.71-perf, uid census known). All work read-only except: ACS config writes (long-standing primitive), device power-cycles, and our own SNTP answers. Red lines unchanged: no OTA/firmware installs, no factoryreset, no USB/hardware, provisioning untouched. Device is LIVE and healthy (boot #3, up 30+ min, clock = 1970-epoch + our accumulated offset, poller + helper v4 + netwatch running, sntp_server.py follow-mode on Mac).

## 1. TODAY'S RESULT — clock-control chain PROVEN end-to-end. Please verify.

Chain: ACS SetParameterValues → 8785 (NtpTrustedTime.LocalSocketService, system_server) → Settings.Global ntp_server_1..5 → boot refresh → unresolvable slot-0 canary DNS-fails → ASKEY retry rotation (10s) → slot-1 = <tester-host> → SNTP request → our responder → SntpClient accepts → SystemClock.setCurrentTimeMillis.

Evidence (all archived under /Users/arnaugonzalezvargas/movistar-home-tr069/):
- Settings.Global readback (helper app): 4 of 5 ntp slots are ours, verbatim (3 injection canaries stored raw → store-only, confirmed).
- 8785 live readback from Termux, 3-token framing `get>...>0>...>x` (2-token framing enters the replace branch — corrects our earlier silence): returned mServers[] matching Settings.
- Requests to our :123 with req[0]=0x1B (8.1 SntpClient). Responses: 48B, stratum 1, mode 4, originate echoed.
- Follow mode (serve client_tx + 6s): ACCEPTED repeatedly. Measurements:
  - JOB-34: uptime 14 min, clock = boot-epoch +28s.
  - Helper currentTimeMillis: 904.456s at 876s wall-since-boot (+28.45s).
  - JOB-35: uptime 16 min, +30s.
  - JOB-36 time series (10 samples/min, reports/2026-10-11-CLOCK-CONTROL-PROOF.md): offset +29s → +40s over 10 min, growing in +6s increments at ~5-min renewal cadence (router lease).
- Crash forensics: while we served ABS-mode (Mac 2026) answers at uptime <2 min, the device hard-reset ~7–14 min later, three times (11:09, 11:24, 11:31 boots). Fresh kernel.log tail shows NO panic/oops/shutdown — mid-chatter cut straight to "Booting Linux" = subsystem/PMIC-level reset (suspect modem/SSR fed insane absolute times via qcom timeservice). +6s steps: stable 30+ min. We control step size.
- Note the model correction: onAvailable sends event=3 (not 1); the 24h gate blocked all our earlier wifi-blip attempts because the boot-time sync resets at each boot; DHCP lease renewals re-trigger polls (ASKEY addition) — that's why the device re-syncs every ~5 min now.
- ACTION PENDING (user's call): restore real 2026 time via `sudo python3 sntp_server.py 0` (abs mode), accepting one possible delayed hard-reset; revert = follow mode.

Review ask #1: sanity-check the offset math and the follow-mode acceptance reasoning (esp. SntpClient offset computation in this ROM: services-src framework sources are on disk).

## 2. EXTERNAL "ROOT OVER WIFI" PLAN — I REJECTED IT at the SELinux seapp gate. Please independently verify the rejection.

Claims to check against /Users/arnaugonzalezvargas/Documents/Codex/2026-10-10/mind/work/rev5-dump/ (system.bin, and our extracted services-src):
a. seapp_contexts has exactly ONE uid-2000 line: `user=shell seinfo=platform domain=shell type=shell_data_file` (extracted from system.bin at file offset ≈116117844).
b. mac_permissions.xml maps exactly two signers, both ASKEY certs (CN=Askey, anderson_yang@askey.com, 2019→2046), both → seinfo=platform. No testkey entry, no <default>. (Extracted near the same offset region.)
c. Therefore a payload APK signed with any non-Askey key gets seinfo=default → no seapp line matches uid 2000 → zygote selinux_android_setcontext fails → spawn aborts. The plan's §4 signing rationale is inverted.
d. The install-time half of the plan DOES work statically: PMS pre-creates SharedUser android.uid.shell uid 2000 every boot (services-src PMS:1684-1689), com.android.shell is deleted from the image (no member packages), and Settings.java:641-642 adopts ANY signer when the SharedUser's signatures are null. So the payload installs at uid 2000 but never runs. Confirm this reading.
e. Their TLS claim is wrong: UnsafeOkHttpClientBuilder is used only by HomeZoneApiClient; the SW-update chain uses AppModule.provideOkHttpClient = stock OkHttp with real validation (updater-src on disk). The fake-API transport stays dead; moot anyway since the user has a tap-install channel.
f. Platform cert = ASKEY (mac_permissions) — confirms your earlier signature finding; testkey only matches boot/OTA.

Review ask #2: if you find ANY crack in (a)-(d) — e.g., another seapp line I missed, a vendor seapp file, a different seinfo default, or a name-based line we can hit with android:process — say so. If the rejection stands, the uid-2000 route is closed at the app layer and kernel LPE remains primary.

## 3. State of all paths (current, receipts in README.md)
- PROVEN: ACS full config R/W; 8785 get/insert/replace (incl. live readback); Settings.Global NTP chain → CLOCK CONTROL (above); vendor log/pcap channel (/storage/emulated/0/Askey/Log/, readable from Termux, root-written); pm path oracle; netwatch (default-network callback events); helper app as our eyes (Global dumps, package flags).
- CLOSED with receipts: JDWP (peer-credential gate root/shell-only in device libcutils disasm + zero connect attempts to our @jdwp-control bind across spawns); adbd (exits status 0 ~3ms after fork — no USB gadget, vendor commented out TCP block; revival needs a property write we do not have); su (04750 root:shell, uid gate 0/2000, sepolicy allows shell→su_exec — but no path to uid 2000); DevOptions (deterministic crash in BugReportInPowerPreferenceController via deleted com.android.shell package; shim APK would fix the UI but the 85-pref screen has no network-adb/property-writing toggle → dead end); sharedUserId claims (this §2); iotbridge (4-class stub, negative); TR-069 Download/Upload RPCs (stubs/log-only).
- REMAINING: kernel LPE (primary; kernel.elf extracted, 124,141 symbols, base c0008000, commit_creds c0140e84, prepare_kernel_cred c01413a8, init_cred c14194f8, modprobe_path c1418e84, selinux_enforcing c1561c7c; census: binder ✓, packet_create ✓, perf ✓, keyctl ✓, kgsl/qseecom/diag present (nodes likely fenced), userfaultfd ABSENT, eBPF prog_load ABSENT; all device-side introspection SELinux-fenced). Red-line alternatives: USB/fastboot (bootloader unlocked, testkey boot) — frozen.

Review ask #3: for the kernel path — given 3.18.71-perf msm8953 2021-10 patch level, 32-bit, no userfaultfd/eBPF: which bug classes do you consider highest-yield to investigate first, and do you see anything in the symbol census worth prioritizing? Artifacts: loot/kernel.elf, loot/kernel-symbols.txt.

## 4. Open question you may be able to settle offline
- Which vendor component hard-resets on large clock jumps (no AP-side trace)? Candidate: qcom timeservice (com.qualcomm.timeservice package + ATFWD), modem SSR. Not needed for the proof; useful if we ever want large controlled steps.
- The iotbridge hourly startForegroundService crash — benign, but its recovery-data file (data/iotbridge.bin) is written by troya-iot-legacy-service; not audited. Low priority.

## 5. Artifacts index (Mac, ~/movistar-home-tr069/)
- reports/2026-10-11-CLOCK-CONTROL-PROOF.md (full receipts incl. time series)
- reports/2026-10-11-sol-handoff.md (this file)
- README.md (complete session log), NEXT-STEPS.md, TONIGHT.md (superseded — proof complete)
- loot/: kernel.elf, kernel-symbols.txt, crash.log, device.log, device-props.txt, kernel-fresh.log, crash-fresh.log, libcutils.so, libbase.so, libart.so, iotbridge.apk
- pcaps/: vendor tcpdump rotations (incl. blip + boot windows)
- services-src/, framework-src/, updater-src/, tr69-src/, socket-src/, troya-src/, iotbridge-src/ (all decompiled)
- helper/ (source; MH-Helper.apk v4 served at :8010), sntp_server.py (abs + follow modes)

No device actions requested of you. Reply in-session or via a note in mind/outputs/ as before.
