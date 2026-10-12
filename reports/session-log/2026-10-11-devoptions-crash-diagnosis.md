# Developer Options crash — diagnosis report (Pi → Sol, 2026-10-11)

Read-only execution of `pi-handoff.md`. No reset/unlock/flashing/toggles/kills. Device state unchanged; only log reads and one world-readable APK path census were performed.

## Observed log evidence (crash.log, uploaded loot/crash.log)

Seven `com.android.settings` FATAL crashes; the user's reproductions at **10-10 17:31:04**, **17:32:59**, **17:33:14** (consistent with unlock-then-open, retried). No settings crash today. Full stack (17:32:59, PID 1506):

```
FATAL EXCEPTION: main
Process: com.android.settings, PID: 1506
java.lang.RuntimeException: Unable to resume activity {com.android.settings/com.android.settings.SubSettings}:
java.lang.IllegalArgumentException: Unknown component: com.android.shell/com.android.shell.BugreportStorageProvider
  at android.app.ActivityThread.performResumeActivity(ActivityThread.java:3584)
  ...
  Caused by: java.lang.IllegalArgumentException: Unknown component: com.android.shell/com.android.shell.BugreportStorageProvider
  at android.content.pm.IPackageManager$Stub$Proxy.setComponentEnabledSetting(IPackageManager.java:4732)
  at com.android.settings.development.BugReportInPowerPreferenceController.setBugreportStorageProviderStatus(BugReportInPowerPreferenceController.java:115)
  at ...updateBugreportOptions(:108)
  at com.android.settings.development.DevelopmentSettings.updateBugreportOptions(DevelopmentSettings.java:1094)
  at ...DevelopmentSettings.updateAllOptions(:834)
  at ...DevelopmentSettings.setPrefsEnabledState(:667)
  at com.android.settings.development.DevelopmentSettings.onResume(DevelopmentSettings.java:698)
```

`Devices lock task mode pinned.` — **absent** from all logs (candidate 2 excluded).

## Diagnosis

- The unlock succeeds and the REAL DevelopmentSettings fragment is reached: `onCreate` completes; death occurs in **onResume → updateAllOptions**. Candidate 1 (DevelopmentSettingsDisabledActivity toast-finish) excluded.
- Root cause is a variant of candidate 3, but not the missing-preference-keys variant: it is a **missing package**.
- Live check (read-only): `/system/priv-app/` contains **no Shell directory and no *shell*.apk anywhere under /system (maxdepth 3)**. The vendor deleted the entire `com.android.shell` package. Stock Settings' `BugReportInPowerPreferenceController.setBugreportStorageProviderStatus()` unconditionally calls `PackageManager.setComponentEnabledSetting(ComponentName("com.android.shell","com.android.shell.BugreportStorageProvider"))`; PMS raises IAE for an unknown component/package → deterministic crash on every DevOptions resume.
- Consequence: Developer Options is unusable on this ROM as shipped. Fixing it requires modifying /system (re-adding a com.android.shell package or patching Settings.apk) — i.e., the already-root-gated path. The USB-debugging toggle is unreachable in the UI; note it would not help anyway: adbd has no transport (no USB gadget; TCP block commented out in init.askey.rc; see README 10:10 entry).
- Theoretical side observation: since com.android.shell is simply absent (not installed), an ordinary sideloaded APK *named* com.android.shell (own uid, no sharedUserId) would make the component resolvable and stop the crash — but it grants no privilege (BugreportStorageProvider would be ours, useless) and DevOptions still offers no path to a shell on this build. Recorded for completeness, not proposed.

## Method note

Your bounded read-only protocol was followed: crash.log/device.log excerpts read after reproduction; timestamps checked (yesterday's 17:31–17:33 crashes = the reported reproductions; today's FATALs are all the unrelated hourly com.smartiotlabs.iotbridge.service RemoteServiceException). No jobs were displaced (job queue was idle; the poller jobs 19/19b performed only `ls`).

## Bonus census (job 19b, read-only)

Full /system/priv-app list captured — includes Provision, SnapdragonGallery, StorageManager, SocketService, and 19 troya-* apps (several we had not seen: quiz, music, routines, notifications-service, support, contacts, comms, events-sender, tv-service, iot-service, iot-legacy-service, auth-service, config-service, updater, settings, onboarding, launcher, zoom). Saved in README.
