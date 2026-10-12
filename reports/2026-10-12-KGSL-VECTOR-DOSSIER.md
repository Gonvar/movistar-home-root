# KGSL root vector — full dossier for next session
Target: ASKEY RG3205W / msm8953 / Adreno 506 / kernel 3.18.71-perf armv7 / **no KASLR** /
SELinux enforcing / one CPU context, untrusted_app uid 10042 (Termux).
Toolchain for this dossier: REA 6.4.0 + Ghidra 12.1.4 on the *device* kernel.
All code below is decompiled from the shipped kernel (`loot/kernel.elf`), not from
upstream. Source cross-check trees: `kgsl-src/` (vulnerable), `kgsl-18/` (fixed line).

Reduced-analysis artifacts (REA needs a small ELF; 26 MB kernel times out):
- `rea-work/kern/kgsl.exec.elf` — VMA `0xc050e000..0xc0528000`, 444 procedures,
  symbols from `loot/kernel-symbols.txt`.
- Pseudocode dump: `rea-work/kern/kgsl/*.pseudo.c` (+ `.json` = full Evidence).
- Rebuild script pattern is in `reports/2026-10-12-REA-FIRMWARE-ANALYSIS.md`.

---

## 1. The bug that is binary-confirmed absent

Vendor fix `0a4ef64e3f` — "Return mementry only if pending_free is not set".

`kgsl-18/kgsl.c:1256` (fixed) vs `kgsl-src/kgsl.c:1204` (our device):
```c
idr_for_each_entry(&private->mem_idr, entry, id) {
    if (GPUADDR_IN_MEMDESC(gpuaddr, &entry->memdesc)) {
        if (!entry->pending_free)          // <-- THE FIX; ABSENT in device
            ret = kgsl_mem_entry_get(entry);
        break;
    }
}
```
Device `kgsl_sharedmem_find` @**0xc050f728** (Evidence `ev_e53efb1501812c8e7395bc4c07ba351659d4decc4091990f3f0a38b036e81628`):
```c
spin_lock(&private->mem_lock);
idr_for_each_entry(&private->mem_idr, entry, id)
    if (GPUADDR_IN_MEMDESC(gpuaddr, &entry->memdesc)) {
        kref_get_unless_zero(entry);       // no pending_free test
        break;
    }
spin_unlock(&private->mem_lock);
```
Device `kgsl_sharedmem_find_id` @**0xc0512520** (Evidence `ev_265fa419a70b76945d6e9212d423bbbf20ece4688aac751d0cb7f23c264e22e2`):
`drain_workqueue(kgsl_driver.mem_workqueue)` → `idr_find` → `kref_get_unless_zero`,
**no pending_free test**.

`pending_free` field = **entry+0x78** (binary: `piVar2[0x1e]` in `kgsl_release`).
`kgsl_mem_entry_get` = `kref_get_unless_zero(&entry->refcount)` (`kgsl-src/kgsl.h:473`).
`find`/`find_id` also take a ref, so the returned entry is not freed under the caller —
the bug is that a *pending-free (owner-relinquished)* entry is handed out at all, which
`get_mmap_entry`, the CP parser, and the ioctls all rely on.

---

## 2. The control-flow sink (binary-confirmed)

`kgsl_gpumem_vm_fault` @**0xc050f130** (Evidence `ev_e6c3ca01fb97df3e3bc4d4933e858d924eba077fe78d31d7570d40446367c775`):
```c
entry = *(void**)(vma + 0x54);                 // vma->vm_private_data
if (entry && *(void**)(entry + 0x40) &&        // entry->memdesc.ops
    (f = *(void**)(*(void**)(entry + 0x40) + 4)))   // ops->vmfault
    return f(entry + 8, vma, vmf);             // indirect call: (memdesc, vma, vmf)
return VM_FAULT_SIGBUS;
```
`entry+0x40` = `memdesc.ops`; `ops+4` = `vmfault`. **A reclaimed freed `kgsl_mem_entry`
⇒ RIP control** with r0 = `entry+8`, r1 = vma, r2 = vmf. No usercopy / STRBT wall involved.

Ops tables read from the image:
| symbol | addr | layout |
|---|---|---|
| `kgsl_page_alloc_ops` | 0xc14592d4 | `[vmflags=0x4060000, vmfault=0xc051d80c, free=0xc051dbf0, map_kernel=0xc051d714, unmap_kernel=0xc051db6c]` |
| `kgsl_cma_ops` | 0xc1459210 | `[0x4060400, vmfault=0xc051db04, free=0xc051d61c, …]` |
| `kgsl_gpumem_vm_ops` | 0xc1458368 | `[open=0xc050f0d8, close=0xc051178c, fault=0xc050f130]` (vma->vm_ops) |

`kgsl_page_alloc_vmfault` @**0xc051d80c** (Evidence `ev_2aaa8b8d10b5608c5ace02b742e3c9726be89632bc9d858cb7c5272d758377e7`)
uses `memdesc->pages` (entry+0x58) and `memdesc->page_count` (entry+0x5c); it does **not**
touch `entry->priv`, so the RIP path is purely via `ops`.

---

## 3. Exact struct offsets (device binary; kmalloc sizes)

`struct kgsl_mem_entry` (base **E**) — allocated by `kzalloc` (`kgsl_mem_entry_create`,
`kgsl-src/kgsl.c:251`), freed by `kfree` ⇒ **generic kmalloc, size ≈0xd0 → kmalloc-256**:
| field | off | note |
|---|---|---|
| refcount (kref) | 0x00 | `kref_get_unless_zero` |
| memdesc | 0x08 | 0x58 bytes |
| memdesc.useraddr | 0x14 | checked by get_mmap_entry (−EBUSY if ≠0) |
| memdesc.gpuaddr | 0x18 | |
| memdesc.size | 0x28 | 64-bit |
| memdesc.priv | 0x38 | bit0 = guard page |
| memdesc.sgt | 0x3c | |
| **memdesc.ops** | **0x40** | **hijack field** |
| memdesc.flags | 0x48 | bit 0x10000000 = SVM; 0xe0>>5 = mem type |
| memdesc.pages | 0x58 | used by vmfault |
| memdesc.page_count | 0x5c | |
| priv_data | 0x60 | ION ptr |
| node (rb_node) | 0x64 | |
| id | 0x70 | idr id |
| priv (kgsl_process_private*) | 0x74 | |
| **pending_free** | **0x78** | **guard missing** |
| metadata[] | 0x7c | |
| work (work_struct) | 0xc0 | `_deferred_put` = `container_of(work,entry,work)` |

`struct kgsl_process_private` (base **P**) — dedicated kmem_cache `_DAT_c154f6d0`
(size arg 0x118), **not** generic kmalloc:
| field | off |
|---|---|
| pid | 0x04 |
| mem_lock (spinlock) | 0x18 |
| refcount (kref) | 0x1c |
| mem_idr | 0x20 |
| pagetable | 0x3c |
| list | 0x40 |
| stats[] (8×16B) | 0x70 |
| syncsource_idr | 0xf0 |
| syncsource_lock | 0x10c |
| **fd_count** | **0x110** |

`struct kgsl_device_private` (per-fd): `device` @0x00, `process_priv` @0x04; stored in
`file->private_data`.
vma: `vm_private_data` @vma+**0x54**; the mapping uses `vm_ops = kgsl_gpumem_vm_ops`.

---

## 4. The refcount / lifetime model (decompiled)

- `kgsl_mem_entry_create`: `kzalloc` → refcount = 2, caller returns 1 to the ioctl.
- `gpumem_alloc_entry`/`kgsl_ioctl_gpumem_alloc_id` (0xc0515f70): after alloc refcount = **1 (user)**; attached via `kgsl_mem_entry_attach_process` (0xc0511f3c) which **takes a private ref** (`kref_get_unless_zero(P+0x1c)`), assigns id (P+0x20 idr) and priv (E+0x74), maps gpuaddr.
- `kgsl_mmap` @0xc0512a98 → `get_mmap_entry` @0xc05125e4: `find_id(pgoff)` then `find(pgoff<<12)`; on success stores E in `vma->vm_private_data` (**owns a ref**). On error it `kref_put`s.
- `kgsl_get_unmapped_area` @0xc051271c: same lookup, then puts (the later mmap re-gets).
- `kgsl_gpumem_vm_open` (0xc050f0d8): `kref_get_unless_zero(vm_private_data)`; sets it to 0 if zero.
- `kgsl_gpumem_vm_close` (0xc051178c): `memdesc.useraddr = 0`; `kref_put`; if 0 → `kgsl_mem_entry_destroy`.
- `gpumem_free_entry` @**0xc05113e0** (Evidence `ev_68eb3ea06fc6d0269bd60a84dea867e592ffe8e8d6d5d79d327704a224006800`):
  ```c
  spin_lock(priv->mem_lock);
  was = entry->pending_free;
  if (!was) entry->pending_free = 1;
  spin_unlock(...);
  if (was) return -EBUSY;        // already pending → no put
  ...perf...
  kref_put(entry);               // drops the USER ref
  ```
- `kgsl_ioctl_gpumem_free_id` (0xc051419c): `E = find_id(id)` (unguarded) → `gpumem_free_entry(E)` → `kref_put(E)` (the find ref). Balanced.
- `kgsl_release` @0xc0511ca4 (Evidence `ev_b68e99134f7346f13767dce84dae5a6e649eed79edf4fdd2f0bfb0639b140416`) — the last-fd teardown:
  `if (--private->fd_count < 1)` { `kgsl_process_uninit_sysfs`; `kgsl_mmu_detach_pagetable`; `list_del(private->list)`; **`process_release_memory`**: for each idr entry, if `pending_free==0` set it and `kref_put`; `kgsl_process_private_put`; `kfree(dev_priv)`. }
- `kgsl_mem_entry_destroy` @0xc051284: `detach_process` → accounting → `kgsl_sharedmem_free(&memdesc)` → `kfree(entry)`.
- `kgsl_mem_entry_detach_process` @0xc0511f0: `spin_lock(E->priv->mem_lock)`; `radix_tree_delete(E->priv->mem_idr, id)`; `kgsl_mmu_put_gpuaddr(&memdesc)`; `kgsl_process_private_put(E->priv)`; `E->priv=0`.
- `kgsl_destroy_process_private` @0xc050f6ec: `idr_destroy`; `kgsl_mmu_putpagetable`; `kfree(private)`.
- `_deferred_put` @0xc05113a8: `kgsl_mem_entry_put(container_of(work,entry,work))` (fence/free deferred).

Net: every entry holds a private ref, so the private outlives its entries in the normal
flow. That is why the simple probes were negative.

---

## 5. Why the missing check is exploitable (leading hypothesis, still to prove)

`pending_free=1` means *ownership relinquished* but the entry is still in `mem_idr` and
still mapped (idr removal + `kgsl_mmu_put_gpuaddr` happen only in `detach_process`, i.e.
at `kref==0`). The fix makes `find`/`find_id` refuse such entries. Without it a caller can
take a **new reference to an entry that is mid-teardown**, and re-publish it (e.g. map it
into a fresh vma through `get_mmap_entry`).

Key enabler: `kgsl_gpumem_vm_close` sets `memdesc.useraddr = 0`, so once a first vma is
unmapped, `get_mmap_entry`'s `useraddr != 0` guard stops blocking a *second* `mmap` of the
same pending-free entry.

Candidate orderings to test (all unprivileged, deterministic except where noted):

- **O1 — pending-free entry is still returned.** alloc E; `mmap` vma_A; `GPUMEM_FREE_ID`
  (pending_free=1, vma ref keeps E alive). Then `GPUMEM_GET_INFO(id)` / re-`mmap`.
  Pre-fix: returns/maps E; fixed: NULL / −EINVAL. *(Core behaviour of the fix.)*
- **O2 — resurrect into a second vma.** from O1 with `useraddr==0` (after munmap vma_A
  while an extra ref is held), `mmap` again → `get_mmap_entry` returns the pending-free E
  and installs `vm_private_data=E`. Then force E to `kref==0` / `kfree` while vma_B remains
  `E` → fault vma_B → `ops` hijack.
- **O3 — spawn-race ref.** keep a transient find ref (thread in `GET_INFO`/`FREE_ID`) while
  another thread `munmap`s the vma and re-`mmap`s, so E survives `vm_close` with
  `pending_free=1` and `useraddr=0`, then reaches O2. *(race-gated)*
- **O4 — double free via unguarded find.** look for any path that `kref_put`s an entry it
  did not `kref_get` once `pending_free` is set; `gpumem_free_entry` is guarded, but
  `vm_close`, `get_mmap_entry` error, and `free_id`'s put are not pending-aware.

The exact free→UAF interleaving is **not yet proven**; treat O1→O2 as the primary and use
O3/O4 as alternates. The earlier surface-2 probes (`kgsl-1905b/c`) were negative precisely
because the vma ref + `set_pend` guard hold for the *quiescent* single-owner case.

---

## 6. Reclaim recipe

- Object freed: `kgsl_mem_entry`, **kmalloc-256**, `kfree` (generic) → spray with any
  controlled kmalloc-256 primitive (e.g. `msg_msg`, `sendmsg` with `SCM_RIGHTS`/control
  buffer, `setxattr`, `add_key`). Layout needed at offset 0x40 → pointer to a fake ops
  table whose `+4` is the target.
- `entry->memdesc.ops` is dereferenced as a **kernel read**; the fake ops table may live in
  a second sprayed object, or (to test) in a **user mapping** — a user pointer for `ops`
  only works if this 3.18 kernel can do a supervisor load from a user page (the earlier
  work found kernel direct-map *stores* hit the AP gate; loads were not settled). Test both.
- After reclaim, trigger `kgsl_gpumem_vm_fault` by touching the still-live vma_B mapping.

No KASLR: fixed gadget/function addresses. Known: `commit_creds` 0xc0140e84,
`prepare_kernel_cred` 0xc01413a8, `init_cred` 0xc14194f8, `selinux_enforcing` 0xc1561c7c,
`modprobe_path` 0xc1418e84. r0 at the indirect call = `entry+8` (controlled content) → a
stack pivot on r0 or a direct data-only target are both on the table. The
**CVE-2019-2215 arbitrary physmap READ** is available as the locate/verify oracle.

Hook the fake `vmfault` to a *distinctive but harmless* kernel pointer first (e.g. a
function that returns a recognisable value) and watch for the call + return, before
escalating to `commit_creds`.

---

## 7. Reachability / ioctls / harness

Confirmed reachable from untrusted_app (prior work): `open /dev/kgsl-3d0`, `GPUMEM_ALLOC_ID`,
`GPUMEM_GET_INFO`, `GPUMEM_FREE_ID`, `mmap`, `DRAWCTXT_CREATE`, `GPU_COMMAND`.
Ioctls (from `binder-exploit/kgsl-cp.c`, `KGSL_IOC_TYPE=0x09`):
`CTXT_CREATE=0x13`, `CTXT_DESTROY=0x14`, `PMEM_ALLOC_ID=0x34`, `PMEM_FREE_ID=0x35`,
`PMEM_GET_INFO=0x36`, `GPU_COMMAND=0x4A`.
Existing harnesses to extend (all compiled arm32-musl; avoid `clock_gettime` → syscall 403
SIGSYS, use `syscall(263,...)`):
- `binder-exploit/kgsl-1905.c` — recycled-tgid private confusion (CONFIRMED, JOB-97).
- `binder-exploit/kgsl-1905b.c` / `kgsl-1905c.c` — negative surface-2 probes.
- `binder-exploit/kgsl-cp.c` + `kgsl-cp` — CP_MEM_WRITE GPU write primitive (session 7).
- `binder-exploit/kgsl-probe.c`, `kgsl-svm{,2,3}.c`.

`kgsl_open` @0xc0510358 (Evidence `ev_755a6ccfe554d467b7b72c1328bd91e83ac81423de2852cd4703abd6a84b44bc`)
matches a private by **bare pid number** (`for (p = process_list; …) if (p->pid == tgid) …`)
and allocates a new private from the dedicated cache when none matches — this is the 1905
confusion, deterministic.

---

## 8. Evidence index (retained this session)

`kgsl_sharedmem_find` ev_e53efb15…1628 · `kgsl_sharedmem_find_id` ev_265fa419…22e2 ·
`kgsl_gpumem_vm_fault` ev_e6c3ca01…c775 · `kgsl_open` ev_755a6ccf…44bc ·
`kgsl_release` ev_b68e9913…0416 · `get_mmap_entry` ev_728f3592…41d0 ·
`kgsl_gpumem_vm_open` ev_7558904a…69e9 · `kgsl_gpumem_vm_close` ev_cd752125…e0bc ·
`kgsl_mem_entry_detach_process` ev_bb7e552b…9236 · `kgsl_mem_entry_destroy` ev_97df3f29…bdd5 ·
`kgsl_ioctl_gpumem_free_id` ev_d77502a8…343d · `kgsl_process_private_find` ev_9ff61c63…4c5b ·
`kgsl_process_private_put` ev_a13eebfe…cbeb · `kgsl_ioctl_gpumem_alloc_id` ev_28bfccb9…ca10 ·
`kgsl_ioctl_gpumem_get_info` ev_c40bd458…d7e8 · `gpumem_free_entry` ev_68eb3ea0…6800 ·
`_deferred_put` ev_5ffd9212…0a7a · `kgsl_mem_entry_attach_process` ev_ab819b94…aa43f ·
`kgsl_mem_entry_commit_process` ev_ca63192a…71b1 · `kgsl_mmap` ev_f164c333…5f19 ·
`kgsl_get_unmapped_area` ev_f7061955…64cd9 · `kgsl_destroy_process_private` ev_f0690bd8…1ee03 ·
`kgsl_page_alloc_vmfault` ev_2aaa8b8d…77e7.
Full evidence JSON + `.pseudo.c` in `rea-work/kern/kgsl/`.

---

## 9. First actions next session (ordered)

1. **O1 probe (safe):** build a tiny arm32 binary from `kgsl-1905.c`: alloc E, `mmap`,
   `GPUMEM_FREE_ID`, then `GPUMEM_GET_INFO(id)` and a second `mmap`. Record whether the
   pending-free entry is returned/mapped (expected pre-fix: yes). Confirm on device.
2. **O2 probe:** with a canary `ops`/`gpuaddr`, try to reach `kfree(entry)` while a vma
   still points at it (use the transient-find-ref race and/or the 1905 shared private to
   add a second handle). Watch `dmesg`/kernel log and `/proc/version` for the fake call.
3. If a freed entry + live vma is achieved: spray kmalloc-256 with a fake entry
   (`*(E+0x40)=fake_ops`, `*(fake_ops+4)=probe_fn`), fault the vma, verify the indirect
   call, then pivot (no KASLR).
4. Re-derive offsets if the device kernel differs: re-import `kgsl.exec.elf` and re-read
   `kgsl_gpumem_vm_fault` / `kgsl_ioctl_gpumem_get_info` (self-checking offsets 0x40/0x78).

Risk note: the earlier naive orderings gave `-EBUSY` and no oops; any step that can
`kfree` an entry still pointed at by a vma is a *write/exec* primitive — sandbox the run and
expect a panic on a miss (device down ~15 min; poller must be restarted after reboot).

---

## 10. SESSION-8 UPDATE (2026-10-12) — see `reports/2026-10-12-KGSL-PENDING-FREE-RESULTS.md`

Key corrections/new results (do not re-run these blind):

1. **The 2017 fix `0a4ef64e3f` only guards `kgsl_sharedmem_find()` (by gpuaddr)** —
   upstream text at `0e42ef24…`. The actual **CVE-2021-1905 patches** are
   `d6770f2b86b6` (remove `memdesc->useraddr`/`mapsize`, add `atomic map_count` +
   `check_vma(hostptr,size)`) and `be897e2fa155` (add `memdesc->lock` and
   `if (gpuaddr) return -EBUSY` in `_gpu_set_svm_region()`). NVD: *"use after free
   due to improper handling of memory mapping of multiple processes simultaneously."*
   The SVM/`gpuaddr` sharing, not the pending_free flag, is the 1905 bug.
2. **O1 confirmed** (`kgsl-pend`): after `FREE_ID`, `GET_INFO(id/gpuaddr)` still
   returns the pending_free entry; `re-mmap` blocked only by `useraddr!=0`.
3. **O2 confirmed** (`kgsl-pend2`): `mremap` shrink resets the single shared
   `useraddr` to 0 while the head vma keeps E alive; a second `mmap` then
   resurrects E into a new vma via **both** `find(gpuaddr)` and `find_id` paths.
   This is exactly the behavior the 2017 fix blocks.
4. **Fork is a dead end**: kgsl vmflags `0x4060000` include `VM_DONTCOPY`, so
   `dup_mmap()` never copies the vma (no `vm_ops->open`). Use mremap-shrink instead.
5. **Deterministic CVE-2021-1905 patch#2 trigger, no race** (`kgsl-svmdbl`):
   allocate SVM entry, `mmap` (gpuaddr=G1), mremap-shrink (va_addr->0), `mmap`
   again -> `_gpu_set_svm_region()` runs again and **re-assigns gpuaddr=G2**,
   leaving G1 registered+mapped but untracked. Patch#2 would have returned -EBUSY.
6. **Blocker** (`kgsl-svmstale`): the stale SVM `gpuaddr` (0xb0d…) did **not**
   accept a `CP_MEM_WRITE` even before teardown, while the non-SVM marker
   (0x310000) did — so the SVM region is not in the GPU view. Reclaim also did not
   visibly re-use the freed pages. Next: settle the SVM/GPU page-table question,
   then reclaim with `msg_msg`/page tables and verify with the CVE-2019-2215 read.

New harnesses: `binder-exploit/kgsl-pend.c`, `kgsl-pend2.c`, `kgsl-svmdbl.c`,
`kgsl-svmstale.c` (binaries + `.gz` in repo root, whitelisted in `upload_server.py`).
