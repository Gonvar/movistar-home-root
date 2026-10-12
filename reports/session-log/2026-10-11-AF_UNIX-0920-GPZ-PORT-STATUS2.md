# CVE-2021-0920 — GPZ race port: status 2 (safe harness built; win oracle missing)

Date: 2026-10-11 ~22:22
Scope: continue `2026-10-11-AF_UNIX-0920-EXPLOIT-LEAD.md` on the 3.18/armv7 target.

## What was established this session

1. **Correct race shape (authoritative).** Project Zero RCA
   `0day-RCAs/2021/CVE-2021-0920.md` + blog *"The quantum state of Linux kernel
   garbage collection"*. The candidate fd (`f10'`) is obtained by `MSG_PEEK` on
   `f11`'s queue **during** GC (after candidate selection). A concurrent non-PEEK
   `recvmsg` on `f11` clears `UNIXCB(skb).fp` while blocked on `unix_gc_lock`, so
   the GC's Stage-1 restore misses the child and Stage-2 purges `f10` while a
   `MSG_PEEK` on `f10'` is reading the skb → **sk_buff UAF**. `cbcf01128d0a` fixes
   it by making MSG_PEEK take `unix_gc_lock`.

2. **Ports built** (`binder-exploit/`, all `zig cc -target arm-linux-musleabihf
   -static -O2 -lpthread`, no `clock_gettime`):
   - `unix-gpz.c` — faithful GPZ appendix PoC (bare).
   - `unix-gpz2.c` — + benign `skbuff_head_cache` reclaim (churn no-fd AF_UNIX
     skbs on the GC CPU 3, so a freed victim skb is reused with `UNIXCB.fp==NULL`
     → `scm_fp_dup(NULL)` is a no-op).
   - `unix-gpz3.c` — + the **RCA step the appendix omits**: the final
     `MSG_PEEK f10'` (`r8`) that actually reads the skb being purged.

3. **Safe single-attempt behaviour PROVEN (device stayed up):**
   - JOB-99 `unix-gpz2 1`: survived, `r0=r1=r7=1`.
   - JOB-101 `unix-gpz 1` × 5 **fresh processes** (bare): all survived.
   - JOB-102 `unix-gpz3 1` × 5 fresh processes (churn + final peek): all
     survived, `r0=r1=r7=r8=1`.

4. **JOB-98's panic was NOT a clean single-attempt UAF.** The in-process
   multi-iteration loop is broken: from iter 1 onward `send_fd` fails hundreds of
   times (`send_fd: No error information`, errno 0), so only iter 0 is a valid
   graph. `unix-gpz2 6` showed this directly. JOB-98 (bare, 5 in-process iters)
   likely died in that broken later-iteration state, not on a clean win. This
   *weakens* the earlier "race is hot" conclusion — see correction in
   `2026-10-11-AF_UNIX-0920-GPZ-TRIGGER-DEVICE-DOWN.md`.

## The blocker now: no safe win oracle

- A win makes the GC purge `f10`'s queue (and free `f10`). Confirming that by
  peeking `f10'` after the race dereferences the freed socket → UAF/panic.
- The benign churn reclaim masks skb-UAF wins (the racing peek reads a valid
  no-fd skb), so "survived" cannot be distinguished from "won safely" or "never
  fired".
- The GPZ appendix trigger alone may be incomplete (it omits the final peek);
  even with the peek added (`unix-gpz3`), 5 attempts is far too few for a race
  with unknown (likely low) per-attempt probability on a synchronous-GC 3.18
  kernel where the GC window is short unless deliberately prolonged.

## Concrete next steps (ordered, cheapest first)

1. **Build a userspace win oracle.** `/proc/net/unix` is fully readable (README).
   A win makes the GC collect the graph's garbage SCC, so the number of live
   AF_UNIX sockets drops. Instrument the probe to count `/proc/net/unix` lines
   before/after a trigger with the graph and no churn — a sustained drop across
   attempts is a safe win signal. (Validate the count first on a known-collectable
   2-cycle vs a non-collectable one.)
2. **Calibrate the timing** with that oracle: sweep the `usleep(0xFA)` pre-peek
   delay and the final-peek placement (before/concurrent/after the non-PEEK
   `f11`), and vary the graph size (the RCA: more garbage = longer GC window).
3. **Only then** add the controlled reclaim (make the freed skb's `UNIXCB.fp`
   point at a controlled `scm_fp_list` → leak file pointers / refcount write),
   i.e. `bad_garbage`'s reclaim layer adapted to 3.18's old GC.
4. **Fix the in-process multi-iteration bug** (diagnose the errno-0 `send_fd`
   failures; likely fd/socket state leak — `count_open_fds()` per iter). Needed
   because the race needs many attempts, and fresh-process loops are slow.

## Honest assessment

This remains a multi-session exploit port. The correct trigger is now in hand and
is **safe in single attempts**; the missing piece is a safe oracle + calibration
which must precede any reclaim work. Device is healthy; `job.sh` is idle.

## Artifacts

- `binder-exploit/unix-gpz{,2,3}.c`, `unix-gpz{,2,3}`, `unix-gpz{,2,3}.gz`
- `job.sh` (idle4)
- `reports/2026-10-11-AF_UNIX-0920-GPZ-TRIGGER-DEVICE-DOWN.md` (incident)
- This report.
