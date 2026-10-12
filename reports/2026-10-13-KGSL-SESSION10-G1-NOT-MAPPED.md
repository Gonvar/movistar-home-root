# Session 10 — CORRECTION: the stale-PTE premise is falsified

Target: RG3205W / msm8953 / Adreno 506 / kernel 3.18.71-perf armv7 / no KASLR /
SELinux enforcing / untrusted_app uid 10042 (Termux).

This supersedes the "stale-PTE write primitive is real" conclusion in
`2026-10-12-KGSL-PENDING-FREE-RESULTS.md` §2b and
`2026-10-13-KGSL-SESSION9-STALE-PTE.md`. Two earlier conclusions were wrong; the
harnesses and the reasoning that produced them are kept for transparency.

## 1. Marker-liveness is NOT a mapping test

`kgsl-faulttest` writes to a deliberately **unmapped** `gpuaddr` inside an IB that
then writes a non-SVM marker:

```
[ctl]  good write + marker: mark=0x00001111
[bad]  BADADDR  write + marker: mark=0x00002222   <-- marker still landed
[bad2] BADADDR2 write + marker: mark=0x00003333   <-- marker still landed
```

A GPU translation fault is **non-fatal** here: the CP continues and the marker
retires. Therefore *any* conclusion of the form "the marker landed, so the stale
G1 write succeeded" is invalid. In particular the `kgsl-stalelive` `[4] G1
post-free liveness: (MAPPED)` line proved nothing.

## 2. G1 is genuinely unmapped by the second `_gpu_set_svm_region`

The only reliable test is value-based: perform a GPU write to a region and **read
the CPU alias** (the pages are CPU-coherent, as `kgsl-svmsize` showed). Staged
`kgsl-g1map` run:

```
[1]  after mmap#1: E=3 G1=0xaae96000 v1=0xaae96000
[s0] after mmap#1  G1: v1[0]=0x10010001   MAPPED
[s1] after shrink  G1: v1[0]=0x10020002   MAPPED
[2]  after mmap#2: G2=0xaae92000 v2=0xaae92000
[s2] after mmap#2  G1: v1[0]=0x10020002   NOT mapped   <-- write did not land
[s3] after mmap#2  G2: v1[0]=v2[0]=0x10040004  MAPPED
```

So the first region's mapping exists after `mmap`#1 and survives the `mremap`
shrink, but the **second `_gpu_set_svm_region` removes it**. The entry ends up
tracking `G2` only, with no orphaned GPU mapping for `G1`.

Consequently there is **no stale GPU PTE to reclaim**: the earlier
"write-to-freed-page" primitive does not exist in this tree.

## 3. Why the earlier "reclaim" misses were expected

Given §2, `kgsl-poolreclaim` / `kgsl-reclaim` (8192 × 4 KiB KGSL allocations plus
a 256 MiB anon spray, no hit) were not measuring a reclaimed stale mapping at
all — `G1` had no mapping. Reclaim is still an open question *if* a genuine
dangling GPU mapping can be produced, but the double-region route does not
produce one.

## 4. Where this leaves CVE-2021-1905

Patch #2 (`be897e2fa155`) adds `if (gpuaddr) return -EBUSY` to
`_gpu_set_svm_region`, and patch #1 (`d6770f2b86b6`) replaces the shared
`memdesc->useraddr`/`mapsize` with `map_count` + `check_vma`. The device result
shows the second region *does* tear down the first, so the exploitable
consequence is not an orphaned mapping. Candidate directions that remain, to be
tested:

1. **The failed-map retry path.** In `_gpu_set_svm_region`, if `kgsl_mmu_map`
   rejects (the `KGSL_MEMDESC_MAPPED` guard) the code calls
   `kgsl_mmu_put_gpuaddr` and `_search_range` retries. Inspect whether the first
   region's `kgsl_iommu_addr_entry` (rbtree node) is correctly removed in every
   interleaving, and whether `kgsl_mmu_unmap`'s failure return (`unmapped !=
   size` → `-ENODEV` → `put_gpuaddr` skipped) leaves a node/PTE inconsistency.
2. **Two `kgsl_mem_entry`s for one memdesc** via the two-fd / recycled-tgid
   shared `kgsl_process_private` (the 1905 "multiple processes" wording) so two
   vmas reference one `memdesc` with independent refcounts.
3. **`kgsl_gpumem_vm_fault` → `memdesc->ops` indirect call** remains the RIP sink
   *if* a freed `kgsl_mem_entry` can be reached through a live vma; the
   double-region route no longer supplies that.

## Artifacts

`harnesses/kgsl-faulttest.c` (marker-vs-fault), `harnesses/kgsl-g1map.c`
(staged value-based mapping test), `harnesses/kgsl-reclaim.c`,
`harnesses/kgsl-poolreclaim.c`.
