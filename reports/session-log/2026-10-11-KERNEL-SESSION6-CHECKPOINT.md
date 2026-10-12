# KERNEL PATH — SESSION 6 CHECKPOINT (2026-10-11 ~21:47)

## Why kernel, and the one hard constraint
Every userspace-write primitive is dead: arm32 usercopy stores are **user-mode (STRBT)**
so kernel destinations can never be written (`reports/2026-10-11-FP5-RESULT-USERCOPY-WALL.md`).
Therefore the only viable write path is **GPU/SMMU** (Adreno command-stream writes
translated by the IOMMU — no usercopy, no access_ok, no AP check). CVE-2019-2215 gives a
reliable arbitrary physmap **READ** (locate + verify); we need one GPU-write bug.

## CVE-2021-1905 (kgsl pid-number reuse) — primitive confirmed, endgame hard
- Deterministic inheritance proven on-device (JOB-97): a recycled tgid inherits a dead
  process's `kgsl_process_private` (pagetable + mem_idr).
- Upstream fix = `93fde26e` ("Compare pid pointer instead of TGID") + `22ea8192`
  ("Correct the refcount on current process PID … leading to use after free"); both absent.
- NVD: *"use after free due to improper handling of memory mapping of multiple processes
  simultaneously."*
- The audit (`2026-10-11-KGSL-AUDIT.md`, rounds 4–5) found the known lifetime guards are
  **present** in our target (batch→context refs, pt-switch detach-guard, context→proc_priv
  ref), so the naive stale-TTBR0 chain is closed. Mapping the exact UAF (idr/mmap ordering)
  is a multi-day derivation.

## New clean candidate: KGSL SVM region wrap-around (fix `7a4e12ab`, 2025)
*"Prevent wrap around during user address mapping … a very large input size causing the
region's 64-bit end address to wrap … incorrectly considered valid, ultimately allowing a
use after free."* Our tree has the old rbtree bookkeeping (`kgsl_iommu_set_svm_region`,
`_insert_gpuaddr`, `_find_gpuaddr`, `_remove_gpuaddr`, `_get_unmapped_area*`) with **no
`end <= gpuaddr` guard** (target symbols present; `iommu_addr_in_svm_ranges` absent).

### Confirmed this session (on-device, uid 10042)
- `IOCTL_KGSL_GPUOBJ_IMPORT = _IOWR(0x09, 0x48, struct kgsl_gpuobj_import)` — **works**
  (`nr=0x48 -> id=1`); other candidate numbers → ENOTTY.
- `struct kgsl_gpuobj_import { u64 priv; u64 priv_len; u64 flags; u32 type; u32 id; }`,
  `type=KGSL_USER_MEM_TYPE_ADDR(2)`, `priv=&{u64 virtaddr}`, `priv_len = size`.
- SVM path reachable: `_gpuobj_map_useraddr → kgsl_setup_useraddr → kgsl_setup_anon_useraddr`
  → `kgsl_mmu_set_svm_region(pagetable, hostptr, size)` → `memdesc_sg_virt`.
- Oversized `priv_len` returns **EINVAL** (from `memdesc_sg_virt`, *after* the region set) —
  not ENOMEM — i.e. the region insert itself succeeded for oversized input.
- **But** a following import at the same address **succeeds** (`kgsl-svm2`, steps 1–3) ⇒ the
  plain stale-region theory is wrong: the failed-import path does clean up the region.
  ⇒ the exploitable corruption is **wrap-specific**, in the allocator: `_get_unmapped_area*`
  and the rbtree walk use `entry->base + entry->size`; a wrapped size makes that value
  smaller than the base, so the allocator believes the region is tiny/empty and can hand
  out an address that overlaps a live region → two mem entries share one GPU VA → one is
  unmapped/freed while the other is live → stale SMMU PTE / rbtree-node UAF.

## Next concrete experiments (kernel)
1. **Wrap → overlap test**: insert a wrap-sized region at B (region accepted), then
   `KGSL_GPUOBJ_ALLOC` with `USE_CPU_MAP` (ioctl 0x28) and/or another import and observe
   whether the returned address overlaps B (bookkeeping corrupted). Use `KGSL_GPUOBJ_INFO`
   (0x2a?) to read back ids/gpuaddrs.
2. If overlap is demonstrated: free the live one, re-allocate over the same VA with a
   controlled GPU object, and drive an **Adreno MEM_WRITE** through the stale mapping into a
   reclaimed kernel page; verify with the CVE-2019-2215 physmap READ
   (`selinux_enforcing=0xC1561C7C`, `init_cred=0xC14194F8`).
3. Keep CVE-2021-1905 as the complement (post-inheritance idr/mmap lifetime confusion).

## Artifacts
- Exploits: `binder-exploit/kgsl-svm.c`, `kgsl-svm2.c`; binaries `kgsl-svms`, `kgsl-svms2`
  (raw-served via `upload_server.py` whitelist: `kgsl-svms`, `kgsl-svms2`, `kgsl-svm.gz`).
- Evidence: `uploads/upload-20261011-214612` (import=0x48), `-214645` (huge EINVAL),
  `-214728` (stale-region test: cleaned up).
- KGSL source: `kgsl-src/` (LineageOS 15.1 msm8953, symbol-matched); uapi `kgsl-uapi.h`.
- Device alive and healthy throughout; `/dev/kgsl-3d0` world-writable.

## Update 21:48 — wrap / allocator probe (JOB, `kgsl-svms3`)
```
[1] good import B       -> r=0 id=1
[2] wrap import W (0xFFFFFFFFFFFFF000) -> r=-1 EINVAL
[3] SVM alloc x3 (GPUOBJ_ALLOC 0x45, USE_CPU_MAP) -> r=0 id=2/3/4
[4] good import B again -> r=0        (no stale reservation)
```
- Wrap import reaches the region set then fails in `memdesc_sg_virt` (EINVAL), same as the
  plain-oversize case; it did **not** leave a reservation that blocks later imports.
- `GPUOBJ_ALLOC` (0x45) works; `gpuaddr` read back as 0 (info struct field order in the
  probe is wrong — needs the exact uapi layout), `va_len=0x1000`.
- So the wrap effect is confined to the **allocator's** `entry->base + entry->size` math,
  not the set/remove path. Next experiment must show an `alloc` VA landing inside the
  wrap-inserted region — i.e. fix the `kgsl_gpuobj_info` layout, insert the wrap region,
  then allocate and compare `va_addr` against W.
- Device healthy throughout; no oops; `/dev/kgsl-3d0` fine.

### Immediate next step (fresh session)
1. Fix `struct kgsl_gpuobj_info` field order (uapi: gpuaddr, flags, size, va_len, va_addr, id
   — verify against device by reading a known-good import), then run the wrap→alloc overlap
   test across the whole SVM VA window (0x40000000..0xC0000000).
2. On a positive overlap, chain: free the overlapped live entry, re-allocate a controlled GPU
   object over the same VA, drive an Adreno MEM_WRITE via `KGSL_SUBMIT_COMMANDS` (0x3D /
   `GPU_COMMAND` 0x4A) into a reclaimed kernel page, verify with the CVE-2019-2215 physmap READ.
