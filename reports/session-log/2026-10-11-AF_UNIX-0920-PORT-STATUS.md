# AF_UNIX 0920 — 3.18/armv7 port status (JOB-90..96)

Date: 2026-10-11
Author: research session 5d
Scope: attempt to port the CVE-2021-0920 (AF_UNIX GC vs MSG_PEEK UAF) public
exploit `sgkdev/bad_garbage` to the Movistar Home (ASKEY RG3205W, Android 8.1,
armv7, kernel 3.18.71-perf, untrusted_app uid 10042).

## TL;DR
The trigger *components* now build and run on the device, and the topology is
understood, but **the exploit's win oracle is a race, not a deterministic graph
property** — so a topology-only replica cannot validate. A full port remains a
multi-day effort. Recommend pivoting to the deterministic fallback
(CVE-2021-1905, KGSL pid-reuse) unless we commit the days.

## What was built and PROVEN on-device
All binaries: `zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all`,
run via the `job.sh` poller as uid 10042.

1. **Primitive set works** (`unix-probe`, JOB-90): `socketpair(AF_UNIX, SOCK_DGRAM)`,
   `SCM_RIGHTS` send/recv, and `MSG_PEEK` resurrecting an in-flight fd all succeed.
2. **Resurrection topology works** (`unix-uaf` v1, JOB-91/92): a self-cycle
   candidate resurrected via a kept peer → `peek(X) -> fd 3`. This is the fd you
   need to read a GC candidate's queue.
3. **`close()` fires `unix_gc()`** on any AF_UNIX close when `unix_tot_inflight>0`
   (`af_unix.c`, `unix_release_sock`). Confirmed by the SCC probe.
4. **Seccomp/SELinux hurdles cleared** — a significant, general finding:
   - **SIGSYS = syscall 403 = `clock_gettime64`.** Static musl's `clock_gettime`
     emits the *new* time64 syscall (403); Android 8.1's seccomp predates it and
     SIGSYS-kills the process. The 3.18 kernel has only the **old** number (263).
     **Any static musl binary here must avoid `clock_gettime`/`time()`/`gettimeofday`
     in a seccomp-filtered app, or use raw `syscall(263,...)`.** This burned two
     runs and is worth writing into the project notes.
   - `madvise`, `sched_yield`, `recvmsg`, `sendmsg`, `socket`, `close`, threads: OK.
5. **The candidacy/collection rule (from target `net/unix/garbage.c`)**:
   `unix_gc` selects candidates with `file_count(f) == inflight(f)`; a dec pass
   unlinks skbs only on *candidate* queues. A single self-loop is **never**
   collected (dec leaves inflight=1 → restored). A closed 2-cycle is.
6. **The entry-node trick** (from `bad_garbage/race.c`): the exploit closes the
   *entry* node `b` to simultaneously (a) trigger `unix_gc()` and (b) drop `b`'s
   external ref so the whole SCC becomes collectable. `b_handle` is a real fd
   (non-candidate) until `close(b_handle)` right before the oracle.

## The blocker (JOB-95/96)
`binder-exploit/unix-ring.c` faithfully reproduces `scc_emit`'s SCC:
`b (entry) → a_infl → c[k-1] → … → c[0] → b`, victim skb on `a_infl`, entry
recvq holds `{a_infl, c[0]}`. On device (n=8,k=3):

```
[round 0] peek(b) -> 2 fds 3 6        <- a_infl=3, canary=c[0]=6
  after close(b): canary_empty=0 => SCC survived (not collected)
```

**Root cause of non-collection:** the very fds we obtain to *observe* the result
(`a_dup` and `canary`, both created by `MSG_PEEK`→`scm_fp_dup`→`get_file`) are
extra **external** refs. They raise `file_count(node)` above `inflight(node)`, so
those nodes are not candidates. There is no way to observe a candidate's queue
without a ref that un-candidates it.

Therefore `bad_garbage`'s `canary_empty` win is not "did the GC collect the SCC"
in a quiescent sense — it is **"did the concurrent MSG_PEEK/scm_fp_dup race the
GC's fput"** (the exploit literally labels it `GC-race`). The reference exploit
wins this only with:
- the fault-stall victim (cold-page copy faults inside `skb_copy_datagram_iovec`),
- `double_schedule`/`spin` timing calibration,
- SLUB freelist control (`lib_slubfw`) to place/keep the freed skb,
- a 1500-node ring / 100 fan-out and cgroup-4k grooming.

None of those transfer unchanged to 3.18/armv7, and the win is probabilistic.

## Why a full port is multi-day (not single-session)
Reference is ~11.6k lines; 6.x-only machinery with no 3.18 analogue:
- `lib_slubfw` SLUB-freelist callbacks + `cg-4k` (kmalloc-cg) buckets — 3.18 has
  neither `kmalloc-cg-*` caches nor the same freelist encoding.
- forged multi-skb chains (`skb2→skb3→skb4→skb5`) for SELinux bypass.
- x86_64 dirty-pagetable escalation (`dirtypt.c`, PML4/PML5) — architecturally
  impossible on armv7; replacement endgame not designed.
- `lib_fault` cold-page stalls rely on reclaimable memory; Android has only zram.

## Recommendation
Pick one:
- **(A) Commit to the port** (multi-day): take `bad_garbage` as the base, drop the
  SLUB/x86_64 layers, and re-derive (i) a 3.18 skb freelist groom, (ii) an armv7
  escalation. Highest ceiling, highest cost/risk.
- **(B) Pivot to CVE-2021-1905 (KGSL pid-reuse UAF)** — deterministic (no race),
  reachable via `/dev/kgsl-3d0` (already opened), no SLUB/x86_64 dependency.
  Needs pid recycling + a mem-entry double-free endgame. Much better
  cost/expected-value for a single-operator push.

Standing artifacts: `binder-exploit/unix-uaf.c`, `binder-exploit/unix-ring.c`,
`binder-exploit/unix-probe.c`; evidence `uploads/upload-20261011-20*.bin`.
