# FP5 result — the usercopy wall is real; 2019-2215 write family CLOSED (read stays)

**Date:** 2026-10-11 ~19:10 · JOB-86 · device healthy before, during and after.

## Run output (verbatim, key lines)

```
[+] ticket junk: pre=0x00060006 (equal halves — the fp4 wedge fix, worked: DEL passed instantly)
[*] target=0xc1561c7c (selinux_enforcing)
fences BEFORE: all 5 DENIED (errno=13)          <- consistent with JOB-85
[*] DEL ... feeding seg11 (16B) ... feeding seg12 payload (4 zero bytes)
[*] victim readv=1 (full=21)
[*] BUF_B[0]=ee   (o11 did NOT go to user BUF_B)
[*] BUF_C[0]=ee   (payload did NOT go to user BUF_C)
fences AFTER: all 5 DENIED
verdict: unexpected (readv=1, B=ee, C=ee)
```

## Interpretation (each step airtight)

1. **Reclaim + redirect landed.** If the reclaim had missed, seg11's base would
   be the user `BUF_B` and o11's first byte (0x00) would sit in BUF_B[0]. It
   doesn't — so the freed binder_thread's slot WAS the victim's imported
   array, and the DEL's twin wrote `array+0x54` into `iov[11].base`. The
   NUM_IOVECS=64 fix from fp4 is now **live-proven** (and fp4's wedge was
   itself proof of the same landing).
2. **The kernel-destination copyout faulted.** readv returned the partial
   count of 1 = copy aborted at seg11's destination (kernel slab address),
   exactly the fixup/short-count path. Bytes cannot vanish: they went neither
   to user buffers nor to kernel memory — the copy was refused.
3. **No wedge** (g_junk_pre equal-halves ticket — root-cause fix verified
   live), no corruption, fences unchanged, device stayed healthy, job
   completed and uploaded.

## Root mechanism (now settled, encoding-level)

The arm32 usercopy on this kernel performs stores as **unprivileged
(user-mode) transfers**:

- probe in `copy_page_to_iter` c0201278: encoding `e4c83000` = P=0,W=0 =
  **STRBT** ("as if user mode") — kernel pages deny user-mode access →
  permission fault → fixup → short count.
- `arm_copy_to_user`/`__copy_to_user_std` (c0388e40) is the classic strt-based
  uaccess: every copy-out byte is written as user-mode → kernel destinations
  can never be written, regardless of `addr_limit`.
- The **read** primitive survives because copy-in (`arm_copy_from_user`) uses
  privileged loads — kernel sources read fine. That asymmetry is exactly why
  the leak works and the write cannot.

Consequences (all empirical now, no more flip-flopping between notes):

- **Self-overwrite via redirected iov_base: dead** on both socket
  (addr_limit gate) and pipe (strt AP gate) paths.
- **addr_limit clobber: dead** — the gate is hardware AP, below any
  range check.
- **Any usercopy-based kernel write (cred patch, selinux_enforcing,
  modprobe_path...) from unprivileged context: categorically impossible on
  this kernel.** Consult-sol3's original wall analysis was correct; the
  M4/handoff "no gate" retraction (and my session-4 first reading of the
  probe) were wrong. The live run settles it.

## What CVE-2019-2215 gives us (banked, final)

- **Reliable arbitrary-length forward physmap READ** (~20+ clean runs, live
  task/cred/binder_struct location, all offsets verified). This is a
  first-class primitive: locate + verify anything, anytime.
- The stale-unlink constrained writes (twin values, ticket increments) remain
  what consult-sol3 already analyzed: no control-flow value.

## The write primitive now comes from CVE-2021-1905 (kgsl)

Already **binary-verified present** (KGSL-AUDIT round 5; fixes `93fde26e` /
`22ea8192` absent from our kernel). Why it's the right — arguably the only —
path:

- The GPU path **bypasses usercopy entirely**: Adreno command streams issue
  SMMU-translated memory writes; no strt, no access_ok, no AP check on the
  kernel side of the fence.
- Geometry (audit-verified): pid-number reuse on `kgsl_open`'s process_list
  walk (tgid NUMBER compare, no struct-pid refs) → recycled-tgid process
  inherits a dead process's `kgsl_process_private` (pagetable + mem_idr) →
  lifetime confusion with the GPU in flight → stale mapping → MEM_WRITE
  packets into recycled kernel memory.
- The 2215 physmap read pairs exactly: locate victim objects (pages we can
  recognize), read back GPU-written memory, verify cred/task addresses
  before ever pointing the GPU at them.

Next concrete steps (one run at a time, JOB-based):
1. On-device pid-recycling harness: fork/exit cycles to recycle a tgid, kgsl
   fd inheritance (fork/SCM_RIGHTS), verify private inheritance via
   KGSL_GETPROPERTY / PT_INFO (observable: two "processes" sharing one
   pagetable id).
2. Stale-pagetable write chain per the audit's endgame section (a5xx,
   issueibcmds/submit_commands — the audit queue's remaining surface).
3. Read-primitive verification loop for every stage.

## Corrections to earlier reports

- `2026-10-11-M4-STATUS.md` retraction #2 ("no PAN/uaccess gate in the
  copyout path") — **wrong**, see above. Retraction #1 (full-count circular
  proof) remains valid.
- `2026-10-11-HANDOFF.md` §1 "NUM_IOVECS=64 never executed" — it did execute
  at 18:24 (wedge, see FP4-WEDGE-ROOT-CAUSE.md); fp5 re-proved the landing
  safely.
- My session-4 reading of the strbt probe ("DACR D1=client passes kernel
  pages via manager domain") — **wrong**; the store itself is user-mode
  semantics. The empirical run is the arbiter.
