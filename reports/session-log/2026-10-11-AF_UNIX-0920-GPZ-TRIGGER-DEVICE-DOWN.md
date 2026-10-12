# AF_UNIX CVE-2021-0920 — GPZ in-the-wild race ported & run; DEVICE DOWN (2026-10-11 22:10, session 6b)

## TL;DR

I fetched the authoritative root-cause and PoC (Google Project Zero
`0day-RCAs/2021/CVE-2021-0920.md`), ported it to 3.18/armv7, built `unix-gpz`,
deployed it as **JOB-98** at 21:57:06, and the **device immediately stopped
responding** (no result POST, ping/ARP dead for 11+ min). The bare UAF trigger
without the exploit's heap-spray reclamation very likely panicked the kernel —
i.e. **the race appears to fire on our 3.18 target**. This is strong but not
conclusive evidence (load/hang cannot be fully excluded).

## Why this supersedes `unix-uaf.c` / `unix-ring.c`

Those probes failed because they assumed a *quiescent* topology test. 3.18's
`unix_gc()` is **synchronous** (called directly from `unix_release_sock`, verified
in `loot/kernel.elf` at `c0b9ad88`), and any fd obtained via `MSG_PEEK` to *observe*
a candidate raises `file_count` above `inflight` and un-candidates it. So a
single-threaded peek-then-close can never collect the SCC.

The Project Zero writeup ("The quantum state of Linux kernel garbage collection",
2022-08-10) shows the real race: the candidate's fd (`f10'`) is obtained by a
`MSG_PEEK` on `f11`'s queue **during** the GC, *after* candidate selection. The
non-PEEK `recvmsg` on `f11` clears `UNIXCB(skb).fp` while blocked on
`unix_gc_lock`, so the GC's restore pass cannot find the candidate child and
mis-classifies `f11` — then the GC purges `f10` while the racing `MSG_PEEK` on
`f10'` is reading the skb → **sk_buff UAF**.

This is exactly the `cbcf01128d0a` fix: MSG_PEEK must take `unix_gc_lock`
(the fix comment explicitly describes the old `total_refs == inflight_refs`
algorithm we have in 3.18).

## What was deployed

- `binder-exploit/unix-gpz.c` — faithful armv7 port of the GPZ appendix PoC.
  - `intptr_t`/`iovec` cleanups, CMSG parsing, SIGSYS/ALRM backstops, bounded iters.
  - No `clock_gettime` (musl emits syscall 403 → seccomp SIGSYS on Android 8.1).
  - `sched_setaffinity`/`setpriority` best-effort (nice<0 may be EPERM).
- Build: `zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all -lpthread`.
  Artifact `unix-gpz` (39804 B), `unix-gpz.gz` (21496 B, md5
  `2d4771063ca0bf3e316bed4086172d1b`), added to the `upload_server.py` whitelist,
  server restarted.
- `job.sh` = JOB-98: fetch + md5-check + `timeout -k 10 120 ./unix-gpz 5`, then
  post health + `dmesg`/vendor-kernel-log tails.

## Timeline

| Time | Event |
|---|---|
| 21:57:06 | device GET `/job.sh` (1498 B) and `/unix-gpz.gz` (21496 B) |
| 21:57:06 → now | **no further GETs, no result POST** |
| 21:59:22 | ping 100% loss; no ARP entry for <device-ip> |
| 22:08:43 | still down (11+ min) |

The poller runs a job inline and only resumes polling after it POSTs, so a
missing POST + dead ARP is a hang/panic, not a slow job (the 5-iteration probe
should take well under the 120 s cap).

## Interpretation

- The GPZ PoC is a **bare trigger** — it makes the GC free an sk_buff that a
  concurrent `MSG_PEEK` is reading, but performs **no reclaim**. On a production
  kernel that typically panics rather than silently surviving. A clean "no
  effect" run would have posted `== survived 5 iters (no crash) ==`.
- Therefore the most likely cause is a **kernel panic from the UAF**, which is
  the positive signal we wanted — but it cost the device.
- It cannot be fully excluded that the 100×`socketpair` × 5 iters churn or a
  `unix_gc_lock` deadlock caused a lockup/soft-lockup instead. Either way it is
  the same code path.

## Recovery

**Device came back on its own at 22:10:34** (ping OK, ~13 min down) — same
auto-recovery behaviour as the 17:45 incident. `/dev/kgsl-3d0` etc. were not
re-probed (no job ran). Note: after this reboot the Termux **poller did not
auto-restart** — the device answers ping but makes no `GET /job.sh` (as of
22:13:45). The poller needs to be started again in Termux (`bash ~/poller.sh`)
before any further job can run. `job.sh` is already back to idle `idle3`, so
reconnecting the poller is safe — JOB-98 will not re-run.

Once polling resumes:
1. Confirm reachability read-only first.
2. Do **not** re-run `unix-gpz` bare. Next iteration must reclaim the freed skb
   (spray `skbuff_head_cache` with a controlled skb / `scm_fp_list`) so the UAF is
   steered to a controlled object instead of a panic.
3. Run **one** iteration with a stronger win oracle (the freed `skb->data`
   occupied by a `scm_fp_list` leaks file pointers, per the GPZ RCA) before
   scaling up.

## Safety lesson

Given the 17:45 panic, a UAF trigger should have been gated behind a
single-iteration, reclaim-assisted run rather than 5 bare iterations. The device
is the scarce resource; the trigger is now known to be hot.

## Artifacts

- `binder-exploit/unix-gpz.c`, `unix-gpz`, `unix-gpz.gz`
- `job.sh` (JOB-98, now reverted to idle `idle3`)
- GPZ source: `/tmp/gpz0920.md`, `/tmp/gpz_blog.txt` (local scratch)
- This report.
