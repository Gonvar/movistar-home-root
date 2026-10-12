# Session 11 — the zombie remap and the real patch #2 race

Target: RG3205W / msm8953 / Adreno 506 / 3.18.71-perf armv7 / no KASLR /
SELinux enforcing / untrusted_app uid 10042.

Following the session-10 correction (no stale PTE; see
[`2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md`](2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md)),
we re-read the actual upstream fixes and probed the memory-safety consequences.

## 1. Exact upstream fixes (fetched, not paraphrased)

**Patch #1 `d6770f2b86b6`** ("Apply google patch CVE-2021-1905_1 KGSL"):

- `struct kgsl_memdesc` loses `useraddr` / `mapsize`; `struct kgsl_mem_entry`
  gains `atomic_t map_count`.
- `check_vma()` is rewritten to reject any vma whose
  `vm_file->f_op == &kgsl_fops` ("Don't remap memory that we already own").
  The old `check_vma(vma, vmfile, memdesc)` compared `vma->vm_file != vmfile`,
  and the anon-useraddr path passed `vmfile = NULL`, so the check was skipped.
- `get_mmap_entry()`: `if (useraddr != 0) -EBUSY` becomes
  `if (flags & KGSL_MEMFLAGS_USERMEM_ADDR) -EBUSY`.
- `kgsl_gpumem_vm_open/close` inc/dec `map_count`; `kgsl_mmap` incs it.
- `kgsl_ioctl_gpumem_get_info` / `gpuobj_info` stop reporting a `useraddr`.

**Patch #2 `be897e2fa155`** ("Apply google patch CVE-2021-1905_2 KGSL"):

```c
spin_lock(&entry->memdesc.lock);
if (entry->memdesc.gpuaddr) {            /* <-- the missing guard */
    spin_unlock(&entry->memdesc.lock);
    return (unsigned long) -EBUSY;
}
...
```
The commit message: *"Protect access to the gpuaddr here to prevent **multiple
vmas from trying to map a SVM region at the same time**."* `_search_range()`
also propagates `-EBUSY`.

## 2. Device decompilation confirms the vulnerable shape

From the shipped kernel (`kgsl.exec.elf`, symbols from `kgsl-sym.elf`):

- `_gpu_set_svm_region` @ `0xc0510030` — no `memdesc.lock`, no `gpuaddr` guard;
  it writes `entry->memdesc.gpuaddr = addr` then `kgsl_mmu_map`; on failure only
  calls `kgsl_mmu_put_gpuaddr`.
- `kgsl_mmu_map` @ `0xc052577c` — the MAPPED guard is
  `if ((priv & 2) == 0 && (priv & 8) != 0) return -EINVAL;`
  (`GLOBAL=BIT(1)`, `MAPPED=BIT(3)`); MAPPED is set only at the very end.
- `kgsl_mmu_put_gpuaddr` @ `0xc0525f04` — clears `pagetable`/`gpuaddr`; the
  `memdesc->pagetable = NULL` / `gpuaddr = 0` **order** is what patch #2 fixes.

## 3. "Zombie" freed entry is remappable (`harnesses/kgsl-dblcheck.c`)

Sequence: `GPUOBJ_ALLOC` (SVM) → `mmap#1` → `mremap`-shrink → `mmap#2` →
`GPUOBJ_FREE` while both vmas are live → `munmap(v1)` → `mmap#3`.

Result:

```
[3] mmap#2               gpuaddr=0xb4b88000 va=0xb4b88000
[4] free (both vm live)  free rc=0
[5] munmap(v1)           va=0x0
[6] mmap#3 on freed id   -> ZOMBIE REMAP   INFO ok gpuaddr=0xb4b84000
[7] munmap(v2)           va=0x0
[8] free again           rc=-1 errno=16 (EBUSY)
```

So a **freed / pending** `kgsl_mem_entry` is still resolved by `find_id` (kept
alive by vma refs) and can be **re-mapped** because `useraddr` was zeroed by the
mremap. `pending_free` is only a diagnostic — `memfree.list` is a fault-
attribution ring, not a protection, and `kgsl_memfree_purge` only truncates
bookkeeping.

This is the CVE-2021-1905 facilitator: mapping identity is a single shared
`useraddr`, and freeing is decoupled from mapping.

## 4. The real patch #2 target is a two-process race

`mmap` holds `mmap_sem`, so two `mmap`s in the **same** `mm` cannot race. The
comment says "multiple vmas … at the same time", which is the **fork + inherited
kgsl fd** case: parent and child share one `kgsl_device_private` /
`kgsl_process_private` (hence one `memdesc` and pagetable) but have **separate
`mm`s**, so `_gpu_set_svm_region` can run concurrently.

Consequence without the guard: two regions can be mapped while only one is
tracked by `memdesc->gpuaddr`; a racing loser's `kgsl_mmu_put_gpuaddr` can clear
`gpuaddr` (and thus untrack the winner). On `free()`, `kgsl_mmu_put_gpuaddr`
early-returns on `gpuaddr == 0`, leaving an **orphaned GPU mapping to pages that
are then released and reclaimed** — the GPU-write primitive after all, but only
via the race.

`harnesses/kgsl-race.c` implements the fork + inherited-fd, large-entry
(2 MiB, to widen the map window) race and value-tests both candidate regions.
It is the current live experiment.

## 5. Open questions

- Can the race be won deterministically enough on this device?
- Does the orphaned region survive long enough to reclaim the freed pages with a
  kernel object, and can the write be verified with the CVE-2019-2215 physmap
  read?
- Does patch #1's `check_vma` hole (import a KGSL vma as a user address) give a
  simpler, race-free route? `kgsl_setup_anon_useraddr` → `memdesc_sg_virt` →
  `get_user_pages` on a KGSL vma would create a second `kgsl_mem_entry` aliasing
  the first's pages; worth a direct on-device probe.

## Artifacts

`harnesses/kgsl-dblcheck.c`, `harnesses/kgsl-race.c`, `harnesses/kgsl-faulttest.c`,
`harnesses/kgsl-g1map.c`.
