# Advisor consult — KGSL / CVE-2021-1905 on RG3205W (msm8953, kernel 3.18.71 armv7)

**Ask:** I have a deterministic, no-race trigger of the missing `_gpu_set_svm_region`
`gpuaddr` check (CVE-2021-1905 patch #2) on a real device. I want a second opinion on the
cleanest way to convert it into a privilege-escalation primitive, and on which of the open
hypotheses below is most likely correct. Please critique the plan, point out mistakes, and
suggest concrete next experiments.

---

## 0. Target / threat model

- ASKEY RG3205W / Qualcomm msm8953 / Adreno 506 (a5xx) / kernel **3.18.71-perf** armv7 /
  **no KASLR** / SELinux enforcing / **no root yet**.
- Attacker = `untrusted_app` uid 10042 (Termux). `/dev/kgsl-3d0` is world-writable.
- Hard wall already established: on this arm32 kernel, hardened usercopy **stores** compile
  to user-mode `STRBT`, so *no* kernel-write primitive via `copy_from_user`/`copy_to_user`
  is possible (`reports/2026-10-11-FP5-RESULT-USERCOPY-WALL.md`). The only viable write path
  is **GPU/SMMU** (Adreno command stream writes translated by the IOMMU — no usercopy).
- A reliable arbitrary **physical-memory read** exists via CVE-2019-2215 (binder); usable as
  a locate/verify oracle.
- Known symbols (no KASLR): `commit_creds` 0xc0140e84, `prepare_kernel_cred` 0xc01413a8,
  `init_cred` 0xc14194f8, `selinux_enforcing` 0xc1561c7c, `modprobe_path` 0xc1418e84.

## 1. The bugs present in this kernel

### (a) 2017 hardening absent — `kgsl_sharedmem_find()` ignores `pending_free`
Upstream fix `0a4ef64e3f` / `0e42ef24`:
```c
 if (GPUADDR_IN_MEMDESC(gpuaddr, &entry->memdesc)) {
-    ret = kgsl_mem_entry_get(entry);
+    if (!entry->pending_free)
+         ret = kgsl_mem_entry_get(entry);
     break;
 }
```
`kgsl_sharedmem_find_id()` is also unguarded in our tree.

### (b) CVE-2021-1905 — real patches (located this session)
- **Patch #1** (`d6770f2b86b6`): remove `memdesc->useraddr` / `mapsize`; add
  `atomic_t map_count` and a `check_vma(hostptr,size)` that walks `find_vma` and rejects
  vmas backed by `kgsl_fops`. Reason: **one memdesc can be mapped by multiple processes
  simultaneously**, so the single shared `useraddr` is meaningless.
- **Patch #2** (`be897e2fa155`): add `spinlock_t lock` to `struct kgsl_memdesc` and in
  `_gpu_set_svm_region()`:
```c
 spin_lock(&entry->memdesc.lock);
 if (entry->memdesc.gpuaddr) { spin_unlock(...); return (unsigned long)-EBUSY; }
 ret = kgsl_mmu_set_svm_region(private->pagetable, addr, size);
 if (ret) { spin_unlock(...); return ret; }
 entry->memdesc.gpuaddr = addr;
 spin_unlock(...);
 entry->memdesc.pagetable = private->pagetable;
 ret = kgsl_mmu_map(private->pagetable, &entry->memdesc);
 ...
```
NVD for CVE-2021-1905: *"Possible use after free due to improper handling of memory mapping
of multiple processes simultaneously."* Our tree lacks both patches.

## 2. Confirmed on-device evidence

### E1 — `pending_free` entry is still handed out
`GPUMEM_FREE_ID` sets `pending_free=1` and drops the user ref; with a vma ref keeping the
entry alive, `GET_INFO(id)` and `GET_INFO(gpuaddr)` still return it (fix would return
`-EINVAL`). `re-mmap` is blocked only by `useraddr != 0`. ✅

### E2 — resurrection into a second vma, deterministically
`mremap(vma, 2p, 1p, 0)` shrink calls `kgsl_gpumem_vm_close()` on the tail, which writes the
**shared** `entry->memdesc.useraddr = 0` while the head vma still holds the entry. A second
`mmap` then passes `get_mmap_entry()` and installs a new vma via **both** `find(gpuaddr)` and
`find_id` paths. ✅ (This is exactly what the 2017 fix blocks.)

### E3 — fork does not preserve the kgsl vma
kgsl vmflags = `0x4060000` = `VM_DONTDUMP|VM_DONTEXPAND|VM_DONTCOPY`; `dup_mmap()` skips
`VM_DONTCOPY` vmas before `vm_ops->open`, so fork gives no extra ref. Use mremap-shrink.

### E4 — deterministic CVE-2021-1905 patch#2 trigger (NO RACE)
```
GPUOBJ_ALLOC(0x2000, USE_CPU_MAP) -> id
mmap#1  -> INFO gpuaddr=G1 va_addr=G1
mremap shrink 2p->1p -> INFO va_addr=0
mmap#2  -> INFO gpuaddr=G2 va_addr=G2   <-- _gpu_set_svm_region ran again,
                                             re-assigned gpuaddr, left G1 region
                                             registered + mapped but untracked
```
Patch #2 would have returned `-EBUSY` at mmap#2. ✅

### E5 — what the double region actually leaves behind
- A **single** SVM gpuaddr is CP-writable and CPU-coherent (`CP_MEM_WRITE(G,0xBEEF0001)` →
  `v[0]==0xBEEF0001`). ✅
- After the double region, an IB that writes `G1=0xA1A1A1A1`, `G2=0xB2B2B2B2`, marker
  `=0xC3C3C3C3` gives `v1[0]==0xB2B2B2B2`, `v2[0]==0xB2B2B2B2`, `mark==0xC3C3C3C3`.
  ⇒ **G1 and G2 map the same physical pages**; the G1 write landed but was overwritten by
  G2. The CP survives. ✅
- After `GPUOBJ_FREE(E)` + munmap both vmas, a CP write to `G1` is still executed (marker
  liveness write succeeds), i.e. **G1's PTE persists after the pages are freed**. ✅
- A 96×8 KiB fresh-allocation spray did **not** visibly reclaim E's pages (no CPU alias
  showed the magic). Uncertain, not disproven.

## 3. Exploitation model (my current plan)

1. Create SVM entry E; get G1 from mmap#1; mremap-shrink; mmap#2 to assign G2 and leave G1
   stale. Both G1/G2 alias E's pages.
2. Free E (drop user ref + vma refs) → `kgsl_mem_entry_destroy` → `kgsl_mmu_put_gpuaddr(
   memdesc)` unmaps **G2 only**; E's pages are returned to the page allocator, but the SMMU
   PTE at **G1** still points at them.
3. Reclaim E's freed physical pages with a target object (page table? `msg_msg`? another GPU
   object?).
4. Drive `CP_MEM_WRITE(G1, ...)` from an IB → GPU writes into the reclaimed object, bypassing
   the usercopy wall.
5. Escalate: if the reclaimed object is a page table → arbitrary physmap R/W; then patch
   `selinux_enforcing`, overwrite `modprobe_path`, or call `commit_creds`.

Alternative endgame if reclaim is hard: the stale G1 region is also still a **live rbtree
reservation** (`kgsl_iommu_addr_entry`) while `memdesc->gpuaddr` no longer references it, so
the SVM allocator can be made to hand out an overlapping region → two mem entries share one
GPU VA → free-one-while-other-live → stale SMMU PTE (the "wrap/overlap" family). Worth
checking whether G1's rbtree node can be freed/reused independently.

## 4. Open questions for the advisor

1. **Reclaim strategy.** E is a 2-page `kgsl_page_alloc` allocation (order-0 pages, freed via
   `__free_pages`). For an *arbitrary-write*-style primitive the classic target is a **page
   table** (PTEs) or `struct file`/`pipe_buffer`/`msg_msg`. Given only a GPU write (not a
   CPU write), is reclaiming with a **user page table** the right target (GPU writes go to
   physical memory; the CPU then reads the corrupted PTE via the physmap oracle)? Or should
   I first aim for a **GPU-side** object (another `kgsl_memdesc` / sgt) so the alias is
   self-verifying? Which object has the most deterministic kmalloc/page reclaim in 3.18
   from an untrusted app?
2. **Why did the prefree `G1` write appear to fault in one run but land in another?** Same
   code path, different ordering of CPU writes. Is there a plausible reason a second
   `kgsl_mmu_map()` of the same `memdesc` could momentarily invalidate the first mapping
   (e.g. `_iommu_map_sg_sync_pc` doing an unmap/TLB sync), or is this a probe artifact?
3. **Is G1's rbtree node actually leaked?** If so, the SVM allocator's `_search_range`
   should skip G1 forever, and a later `kgsl_mmu_set_svm_region` could overlap after
   `uint64` wrap (the separate 2025 wrap fix is also absent). Could we get a **double-free of
   the same SVM region** (two entries with the same `gpuaddr`) more cheaply than reclaiming
   physical pages?
4. **Patch #1 path.** `memdesc_sg_virt()` uses the shared `useraddr` for `get_user_pages`.
   With two processes mapping one imported memdesc, can we make the kernel pin *attacker
   pages it did not intend* (or a vma it does not own) deterministically? Is there a known
   exploitation of that half of 1905?
5. **Any better CVE-2021-1905 writeup/exploit?** I only found the empty
   `TAKIANFIF/CVE-2021-1905-...` repo. A real PoC or blog would shortcut the endgame.

## 5. Artifacts / repro

- Harnesses: `binder-exploit/kgsl-pend.c`, `kgsl-pend2.c`, `kgsl-svmdbl.c`,
  `kgsl-svmcp.c`, `kgsl-svmdual.c`, `kgsl-svmstale.c` (all arm32-musl static; binaries in
  repo root; served via `upload_server.py`).
- Device results: `uploads/upload-20261012-{122127,122705,122908,123419,123738,123856}*.bin`.
- Notes: `reports/2026-10-12-KGSL-PENDING-FREE-RESULTS.md`,
  `reports/2026-10-12-KGSL-VECTOR-DOSSIER.md` (§10).
- Kernel source (vulnerable): `kgsl-src/`; fixed line: `kgsl-18/`.

## 6. One-paragraph summary

We can deterministically violate the CVE-2021-1905 invariant (`_gpu_set_svm_region` must
refuse when `memdesc.gpuaddr != 0`) with a single process and no race, by abusing the *other*
half of the same CVE (the single shared `memdesc.useraddr`, reset by an `mremap` shrink). The
result is, at minimum, a leaked/untracked live SVM region whose PTE outlives the owning
`kgsl_mem_entry`; we have confirmed the stale PTE is still GPU-executable after the entry is
freed. The remaining work is (i) reliable physical-page reclaim of the freed backing pages or
(ii) a region/PTE double-free, then turning the GPU write into a kernel write. I am asking for
guidance on the reclaim target and on which 1905 sub-bug gives the shortest path to root.
