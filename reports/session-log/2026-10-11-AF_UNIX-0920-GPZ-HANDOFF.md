# HANDOFF — CVE-2021-0920 GPZ race: device down again (JOB-105), instructions for the next agent

Date: 2026-10-11 ~22:25. Author: session 6e/6f.
Device: RG3205W <device-ip> — **DOWN again as of 22:24:40** (ping/ARP dead,
no result POST for JOB-105).

## What happened (be blunt)

I ran a **pre-delay sweep** (JOB-105) of the GPZ MSG_PEEK/unix_gc race with the
recvmsg thread's wake-to-peek delay `pre` from **0µs** upward. The device died
during the sweep. Previous runs with `pre=250µs` (JOB-103/104, 20 attempts) were
all clean. So the panic correlates with **small `pre`** — i.e. the synchronous
3.18 `unix_gc()` window is hit when the non-PEEK dequeue fires immediately after
the recvmsg thread wakes.

**This is the third device kill** (17:45 init_task, 21:57 JOB-98, 22:24 JOB-105).
The first two were arguably avoidable; this one is the risk of the race itself.

## State left behind

- `job.sh` = **idle5** (safe). On reconnect the poller will fetch idle and NOT
  re-run any probe.
- Device must be power-cycled / allowed to auto-recover (it did at 22:10 after
  ~13 min last time).
- The Termux poller does **not** auto-start after reboot — needs `bash ~/poller.sh`.
- Upload server is up on the Mac (`com.movistarhome.uploadserv`, :8010).

## What is proven / not proven

PROVEN:
- The GPZ root cause and race shape (Project Zero RCA + blog).
- 3.18's mis-classification window exists: `unix_detach_fds` sets
  `UNIXCB(skb).fp = NULL` *before* `unix_notinflight` takes `unix_gc_lock`
  (verified `af_unix318.c:2043` / `online 3.18 source`).
- The ported trigger is **safe at `pre=250µs`**: 20 clean attempts (JOB-101/102/103/104).
- The post-race oracle works (detects a drained f10 queue; returned "no win" on
  all 20 clean attempts).

NOT PROVEN / IMPLIED:
- JOB-105 panicked at small `pre`, which **suggests the race does fire** on 3.18
  (the UAF lands and panics because the reclaim/delay is wrong). It is *not*
  confirmed as a UAF vs. a lockup/OOM; there is no post-mortem.

## Artifacts (all in `binder-exploit/` + repo root)

- `unix-gpz.c`  — bare GPZ appendix port (JOB-98/101).
- `unix-gpz2.c` — + benign skbuff churn reclaim (JOB-99/100).
- `unix-gpz3.c` — + RCA's final `MSG_PEEK f10'` step (JOB-102).
- `unix-gpz4.c` — + post-race safe win oracle (JOB-103).
- `unix-gpz5.c` — + tunable `pre`/`delay` argv (JOB-104/105).
  Usage: `./unix-gpz5 <iters> <delay_us> <pre_us>`.
- Build: `zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all -lpthread`.
- Reports: `2026-10-11-AF_UNIX-0920-GPZ-TRIGGER-DEVICE-DOWN.md`,
  `2026-10-11-AF_UNIX-0920-GPZ-PORT-STATUS2.md`, this file.
- GPZ source scratch: `/tmp/gpz0920.md`, `/tmp/gpz_blog.txt`.

## Recommended next steps (SAFEST FIRST — do not repeat my mistake)

1. **Recover the device. Wait for it. Confirm with an idle `job.sh` only.**
2. Do **not** run `pre=0` again without a way to survive the win. The panic at
   small pre means a win happens; the next run must either (a) reclaim the freed
   object with a controlled one so the read is benign/detectable, or (b) drop the
   race probability and accept crashes only in a controlled reboot test.
3. **Find the GC lock window duration** without racing: on a clean boot, time
   `close()` of a socket with N in-flight candidates using `syscall(263,...)`
   (raw `clock_gettime`, NOT libc — seccomp kills 403). If `unix_gc` takes, say,
   50µs, then `pre` must be timed to that.
4. **Widen the window** the RCA way: build thousands of α garbage nodes (raise
   `RLIMIT_NOFILE` to 4096, use many groups). A longer GC means a wider window
   and a `pre` that is robust.
5. **Build the real oracle/reclaim** before racing again: make the freed skb's
   `UNIXCB.fp` point at a controlled `scm_fp_list` (leak file pointers) instead of
   panicking. Only then iterate the race.

## Correction to earlier claims

`2026-10-11-AF_UNIX-0920-GPZ-TRIGGER-DEVICE-DOWN.md` implied JOB-98 showed "the
race is hot". That is **not supported**: JOB-98 was a broken in-process multi-iter
loop (iters 1+ had hundreds of `send_fd` failures). The real hot signal is
JOB-105's small-`pre` panic. Treat the earlier claim as withdrawn.
