# Session 9 — probe-artifact correction; stale PTE confirmed; reclaim is the wall

Target: RG3205W / msm8953 / Adreno 506 / kernel 3.18.71-perf armv7 / no KASLR /
SELinux enforcing / untrusted_app uid 10042 (Termux).

> **SUPERSEDED (session 10).** The §3 conclusion below that "the stale PTE
> survives the free" was based on **marker liveness**, which `kgsl-faulttest`
> later showed is not a mapping test (translation faults are non-fatal). The
> value-based staged test in
> [`2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md`](2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md)
> shows G1 is in fact **unmapped by the second `_gpu_set_svm_region`**. §1
> (probe-artifact correction) and §2 (aliasing) still stand; §3 does not.

This note supersedes the "stale SVM gpuaddr appeared not CP-writable" section of
`2026-10-12-KGSL-PENDING-FREE-RESULTS.md`.

## 1. The "SVM writes never land" result was a **probe artifact**

The `cp_write()` helper used in `kgsl-svmstale.c` / `kgsl-poolreclaim.c` submits
each `CP_MEM_WRITE` as its own `GPU_COMMAND`. KGSL command batches are
**asynchronous**: calling `cp_write()` a second time `memset`s and rebuilds the
**same mapped command buffer** while the first batch may still be executing, so
the second call silently **overwrites the first batch's command stream** before
the CP reads it.

Symptom: marker writes (always last) land, object writes (first) "don't".
Reproduced cleanly in `kgsl-svmsize.c` with separate submits and fixed by putting
the object write and marker **in one IB** and **polling the marker** before
touching the buffer again (`kgsl-stalelive.c`, `kgsl-svmsize.c`).

With the fix, **every** SVM write lands:

```
kgsl-svmsize (single IB [write G, write marker], marker polled):
1p_noprime   gpuaddr=0xb538d000 -> p0=0x51510001 want=0x51510001 mark=0x0f00d000 VAL_LAND
1p_prime     gpuaddr=0xb538c000 -> p0=0x51510002 want=0x51510002 mark=0x0f00d000 VAL_LAND
2p_noprime   gpuaddr=0xb538a000 -> p0=0x51510003 want=0x51510003 mark=0x0f00d000 VAL_LAND
2p_prime     gpuaddr=0xb5388000 -> p0=0x51510004 want=0x51510004 mark=0x0f00d000 VAL_LAND
1p_noprime_nw gpuaddr=0xb5387000 -> p0=0x51510005 want=0x51510005 mark=0x0f00d000 VAL_LAND
1p_prime_nw   gpuaddr=0xb5386000 -> p0=0x51510006 want=0x51510006 mark=0x0f00d000 VAL_LAND
```

(Also observed: a previous `clock_gettime`-based wait died with SIGSYS — syscall
403 is blocked under Termux seccomp. Bounded `usleep` polling is used instead.)

## 2. `G1`/`G2` alias — the "G1 did not land" label was a false negative

`kgsl-svmdual.c` emits **one IB**: `G1=A1; G2=B2; marker=C3`. The CPU aliases
both read `0xB2B2B2B2`. Because `G1` and `G2` map the **same physical pages**,
`B2` simply overwrote `A1`; **both writes landed**. The earlier report wrongly
concluded `G1` was not mapped.

## 3. Stale PTE survives the free — confirmed (`kgsl-stalelive`)

Clean, paired, marker-polled run:

```
[1] E id=3 G1=0xa8547000 G2=0xa8543000 v1=0xa8547000 v2=0xa8543000
[2] sanity G2: rc=0 v2[0]=0x5a5a5a5a v1[0]=0x5a5a5a5a mark=0x000000a1
[3] E freed; INFO rc=-1 errno=22 (destroyed)
[4] G1 post-free liveness: rc=0 mark=0x000000b1 (MAPPED)   <-- stale PTE persists
[6] reclaim scan: 24 x 4 KiB allocs -> no hit at index -1
[5] G2 post-free (control): rc=0 mark=0x000000c1 (still mapped)
```

`[4]` is the key positive: after `GPUOBJ_FREE(E)` and both `munmap`s, the CP
still retires an IB whose first packet writes `G1`. The GPU page-table entry is
stale but live.

## 4. The remaining wall: reclaim

24 fresh 4 KiB SVM allocations did **not** pick up `E`'s freed pages, and an
earlier batched 16 384-allocation drain also missed (that run additionally used
the artifact-prone separate-submit helper, so it must be re-run cleanly).

The advisor's model — freed KGSL pages go to the **KGSL page pool** (FIFO,
`list_add_tail` / `list_first_entry`, zeroed on entry), overflowing to
`__free_pages` only when the per-order pool is full or absent — means pool depth
(device-tree driven via `qcom,gpu-mempools`, unreadable to `untrusted_app` here)
controls how many allocations are needed.

**Next:** re-run the drain with the corrected paired/wait submit; then target a
kernel object reclaim (user L2 PTE page — arm32 `pte_alloc_one` is order-0 — or
`msg_msg`), verifying with the CVE-2019-2215 physmap read.

## Artifacts

`harnesses/kgsl-svmsize.c`, `harnesses/kgsl-svmg1.c`,
`harnesses/kgsl-stalelive.c`, `harnesses/kgsl-poolreclaim.c`.
