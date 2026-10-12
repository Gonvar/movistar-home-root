# DEVICE BOOT FAILURE — INCIDENT REPORT

**Date:** 2026-10-11 ~17:45
**Device:** Movistar Home / ASKEY RG3205W (<device-ip>)
**Status:** Device rebooted and is NOT coming back up. Ping 100% packet loss.

## What was running

JOB-79 = `poc-wq` ("reference timing, SYNC_WAIT=3s"). This was the write-primitive
test that used the reference PoC's 3-second sync wait before triggering the UAF.

**JOB-79 never posted a result.** No upload appeared. Consistent with the device
dying during the run.

## Why it likely crashed

`poc-wq` was the first binary to combine:
- a **3-second** wait with the victim parked in `recvmsg`, and
- a redirect to `0xC1413B08` (`init_task.comm`) / `0xDEADC0DE`.

Two plausible causes, both kernel-memory corruption:

1. **The redirect actually landed this time.** The extra 3s may have made the
   self-overwrite visible (JOB-78 proved the shorter sleeps did NOT). If so, the
   "bogus" round wrote to `0xDEADC0DE` and the "valid" round wrote to
   `init_task.comm`. Writing near/into `init_task` can take the box down hard.
2. **3s of a parked victim + repeated binder/epoll churn** raced into a state the
   driver didn't survive (e.g. list corruption hitting a live object rather than
   the recycled slab).

I cannot distinguish these without a serial console. My honest read: cause (1) is
more likely, meaning **the write primitive may have started working** — which is
also the most dangerous outcome, because it means we were writing to arbitrary
kernel addresses without a verification gate that the write landed where intended.

## Immediate actions taken

- Killed the upload server. **No further device interaction.**
- Moved every write-primitive artifact to `QUARANTINE/`:
  `poc-w{1,2,3,f,g,m,n,o,p,p2,q,r,t,t2,t3}.c`, `poc-fp.c`, `poc-root.c`,
  and all their `.gz` payloads.
- Only read-only binaries remain reachable: `poc-m2.gz` (leak), `poc-m3.gz`,
  `poc-m4.gz`, `probe-surface.gz`.

## Why a boot failure and not just a reboot

Writes to `0xC1413B08` land in the kernel text/data region (near `init_task`).
Corrupting code or the task list can leave the box unable to complete boot —
e.g. a corrupted init path, an unwritable rootfs flagged dirty, or a panic loop
before the network stack comes up. `init_task.comm` itself is cosmetic, so the
damage more likely came from the *redirect machinery* writing adjacent fields,
or from `iov[10].len` having been set to a huge value and the copy walking into
live kernel structures.

## Safety notes

- No firmware writes, no OTA, no factory reset were performed at any point.
- This is a crash from an in-kernel memory-corruption primitive on a device the
  user owns, from their own network. No third-party systems were involved.

## Before doing anything else on this device

1. **Do not run any more write-primitive binaries.** The fault-probe harness is
   sound in principle but the "valid" target in these runs was `init_task.comm`,
   which is not a safe place to be experimenting.
2. Recover the device first (power cycle; if it stays dead, the user's own
   recovery options apply — factory reset is on their red-lines list, so that
   decision is theirs, not mine).
3. If it comes back, **pin the job to read-only** (`poc-m2.gz`) to confirm
   reachability before anything else is pushed.

## Open technical question this raises

If the 3s sync wait was what finally made the redirect visible, then the write
primitive works and the remaining task is to *safely* verify a write landed
some harmless (writable, non-critical, observable) target before ever pointing
it at `init_task` or a `cred`. The `task->comm` test from earlier was the right
idea; it needs a **confirmed-live** target, which is what JOB-69/70 failed to find.

Suggested safe verification target for a future run: a writable global in `.data`
whose effect is observable and harmless, or `task->comm` of a task confirmed live
by cross-checking `comm` against `/proc/<pid>/comm` *before* writing.
---

## RECOVERY — 2026-10-11 17:58

**Device is BACK.** JOB-80 (read-only) ran clean:

```
kernel : 3.18.71-perf #1 SMP PREEMPT ... armv7l Android   (same build)
uid    : 10042 (untrusted_app, no escalation)
array  : 0xd7812c00
iov[10].len  = 0xd7812c54  = self-ptr   <- corruption landed
iov[11].base = 0xd7812c54  = self-ptr   <- corruption landed
exit=0
```

The UAF + corrupted-iovec geometry still reproduces perfectly on the recovered
box. Read primitive confirmed. No reboot, no oops during the read-only run.

### Hardening applied before re-running anything

`poc-m2` still *contained* kwrite/kread code paths even though its `main` only
called the leak — unnecessary risk for a freshly recovered device. Built
`poc-ro` instead: source truncated at the leak boundary, so **no kernel-write
code path exists in the binary at all** (verified via `nm`).

Server state:
```
poc-ro.gz  200   <- read-only leak only, no write code
poc-wq.gz  404
poc-wg.gz  404
poc-root.gz 404
poc-fp.gz  404
```
All write primitives remain quarantined and unservable.

### Note on the crash

The device did come back on its own, so the JOB-79 damage was transient (likely a
panic + auto-recovery rather than persistent corruption). That does NOT mean it
was safe — it means we got lucky. Do not point the primitive at `init_task` or
near kernel text again.

### Next step (requires explicit go-ahead)

Before any write attempt, the target must be:
1. Harmless — cosmetic or a `.data` global with observable, non-critical effect.
2. **Confirmed live first** — cross-check `task->comm` against `/proc/<pid>/comm`
   *before* writing. JOB-69/70 failed precisely because they could not confirm a
   live target.
3. Verified by the fault probe (bogus addr must shorten the count; valid addr
   must reach full). Never treat a bare full count as success.
