# CVE-2021-1905 KGSL pid-reuse — endgame analysis (target 3.18 source)

Date: 2026-10-11
Primitive status: **CONFIRMED on-device** (JOB-97, deterministic).
This note pins the source-level UAF surface and the concrete next experiments.

## The vulnerable design (kgsl-src/, target 3.18)
`kgsl_process_private` is keyed by a bare **tgid number** and every derived
resource is keyed by that number too:

- `kgsl_process_private_new()`:
  `list_for_each_entry(private, &process_list) if (private->pid == tgid) ...`
  `private->pid = tgid;` (a `pid_t`, no `struct pid`, no refcount)
  `private->pagetable = kgsl_mmu_getpagetable(mm, tgid);`
- `kgsl_get_pagetable(name)` walks `pagetable_list` matching `pt->name == name`
  and takes `kref_get_unless_zero`. Pagetable name = the same tgid number.
- `kgsl_process_private_open()`: `if (private->fd_count++ == 0) list_add(...)`
- `kgsl_process_private_close()`: `if (--fd_count > 0) { put; return; }`
  → last fd: `kgsl_mmu_detach_pagetable(pt)`, `list_del(&private->list)`,
  `process_release_memory(private)` (marks every mem entry `pending_free=1` and
  drops its idr ref), `kgsl_process_private_put`.
- `kgsl_destroy_process_private()`: `idr_destroy`, `kgsl_mmu_putpagetable(pt)`,
  `kfree(private)`.

## The fix (kgsl-18/ = LA.UM fixed line, and kgsl-la77/)
`struct pid *cur_pid = get_task_pid(current->group_leader, PIDTYPE_PID);`
compare `private->pid == cur_pid` (pointer identity — a recycled tgid yields a
DIFFERENT `struct pid`, so no match), store the pointer, and
`kgsl_destroy_process_private()` does `put_pid(private->pid)`. Everything else
switches to `pid_nr(private->pid)`.

⇒ The **only** behavior change is: *a recycled tgid no longer matches an existing
private*, and the fixed private holds a `struct pid` ref. So the bug is exactly
"a fresh process inherits a dead process's private".

## Why that is a UAF (the exploitable consequence)
With the number match, a *fresh* process C can end up as the **sole live owner**
of a private whose **original owner A is gone** but whose resources were built
against A's address space / lifetime. Two concrete surfaces:

### Surface 1 — `fd_count`/`list`/pagetable teardown driven by the wrong process
The private's `fd_count` and `list` membership are managed by whoever opens it.
If A's fd is NOT kept alive, A's exit tears the private down normally. The bug
matters when A's fd *is* kept alive (SCM_RIGHTS/fork) so `private_A` (and
`pagetable_A`, name == A-old-tgid) survives with `pid == A-old-tgid`, and then C
reclaims that tgid. Now `pagetable_A` is reachable both as `private_A->pagetable`
*and* by name via `kgsl_mmu_getpagetable(mm, A-old-tgid)`. A later
`kgsl_open` path that legitimately wants a *fresh* pagetable for the recycled
tgid instead gets the stale one; overlapping `detach_pagetable` (from
`kgsl_process_private_close`) with live GPU mappings → **stale SMMU PTEs** (a GPU
write into recycled physical memory — the write primitive we want, and it
bypasses the hardened-usercopy wall entirely).

### Surface 2 — cross-process mem-entry / vma lifetime
`kgsl_mmap` pins the mem entry via `get_mmap_entry()` → `kgsl_mem_entry_get()`
held until `kgsl_gpumem_vm_close()`. The private being shared by two processes
means the *same* `mem_idr`, `entry->memdesc.useraddr`, and pagetable are driven
from two contexts; `process_release_memory` (last-fd path) marks entries
`pending_free` and drops the idr ref while a vma from the other process may
still fault them (`kgsl_gpumem_vm_fault` → `entry->memdesc.ops->vmfault`).

## Next experiments (ordered, all unprivileged)
1. **Pagetable-name reuse probe**: A opens kgsl (creates pagetable named A.tgid),
   allocates a mem entry, maps it; keep fd_A; A exits; recycle A.tgid with C;
   *without* inheriting (force a fresh open after freeing private_A) check whether
   C's `private->pagetable->name == A.tgid` and whether a GPU mapping created by A
   is still live. Detect stale-PTE reuse.
2. **Shared-private free/observe probe**: parent holds fd_A + a live `mmap` of
   entry E; recycled C does `GPUMEM_FREE_ID(E)` then re-`ALLOC`; parent reads its
   mmap and re-`GET_INFO` — look for freed-page reuse (spray) or a device oops.
3. **Stale-SMMU GPU write**: once surface 1 is shown, submit an Adreno MEM_WRITE
   through the stale pagetable into a reclaimed kernel page; verify with the
   working CVE-2019-2215 physmap READ.

## Note on attacker value
The confusion is only exploitable if the private survives without a live,
*authoritative* handle owning it in the attacker's name. The probes above exist
to find that condition empirically (the source alone does not make the ordering
unique).

Artifacts: `binder-exploit/kgsl-1905.c` (primitive, confirmed);
`reports/2026-10-11-CVE-2021-1905-PRIMITIVE-CONFIRMED.md`.
