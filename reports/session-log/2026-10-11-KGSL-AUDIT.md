# kgsl-3d0 Audit — Interim Findings (2026-10-11, session 3)

Target: RG3205W speaker, msm8953, Adreno 506, kernel 3.18.71-perf, kgsl = cmdbatch generation.
Reference source: LineageOS android_kernel_xiaomi_msm8953 lineage-15.1 `drivers/gpu/msm/{kgsl,adreno}` (symbol-set matched to target: `kgsl_cmdbatch_*` present, drawobj absent ✓).
Local copies: `kgsl-src/` (32 kgsl files) + `kgsl-src/adreno-*` (34 adreno files) + `sync-src/` (staging sync).

## Reachability (probed on-device as uid 10042, JOB-61/62)
- `/dev/kgsl-3d0` **OPEN** ✓ — full 34-ioctl surface callable (incl. syncsource, gpuobj, submit_commands)
- `/dev/oneshot_sync` ENOENT (CONFIG_ONESHOT_SYNC_USER not compiled)
- `/dev/sw_sync` EACCES (SELinux); /dev/ion, /dev/graphics/fb0, perf_event_open: EACCES
- add_key, msgget, shmget, mq_open: seccomp SIGSYS — no controlled-content kmalloc spray via keys/SysV-IPC
- NOTE: /system/bin/dnsmasq exists on device (SELinux stat-denied) — Android 8.1 bundled dnsmasq likely < 2.78 → CVE-2017-14491-vulnerable *if running*, but it only runs in tethering/provisioning mode; re-entering provisioning = factory-reset territory → RED LINE. Filed as unreachable-under-constraints.
- TIOCSTI works (no privileged tty session exists → unused).

## Audit findings so far
1. **Dispatcher (kgsl_ioctl_helper)**: clean. Stack `data[128]`, BUG_ON size guard, copy min(ksize,usize), dir-masked. NOTE: no magic check — dispatch on `_IOC_NR(cmd)` only (footgun, not a bug by itself).
2. **gpuobj_import/free/set_info, copy_metadata, cff_syncmem**: bounds-checked, refcount-symmetric. cff paths no-op unless cffdump enabled (module param, default off).
3. **kgsl_mmap / get_mmap_entry / vm_fault / vm_close**: single CPU mapping enforced via `memdesc.useraddr`; entry ref held until vm_close; length checked against footprint. Clean so far.
4. **syncsource/oneshot (kgsl_sync.c, oneshot_sync.c)**: VERDICT CLEAN. kref usage symmetric (`kref_get_unless_zero` under syncsource_lock; destroy steals creation ref after idr-removal — safe by construction). The ref-less `orig_fence` is pointer-identity-compared only (never dereferenced) — safe by design; stale-pointer recycle at worst logically signals own timeline. Foreign fds accepted by signal_fence but only pointer-matched. `/dev/oneshot_sync` not compiled; sw_sync SELinux-blocked.
5. **mem_entry lifecycle (kgsl_mem_entry_destroy / kgsl_sharedmem_free)**: unmap-before-free ordering correct (`kgsl_mmu_put_gpuaddr` → ops->free → pages). `set_page_dirty` walked before free ✓. `memfree.list` = diagnostic only (fault attribution, 512-entry ring) — NOT a protection.
6. **cmdbatch mem refs**: cmdlist/memlist nodes hold ONLY raw {gpuaddr,id,offset,size,flags} — NO mem_entry refs (unlike profiling_buf_entry which refs properly). Protection = SMMU unmap at free → stale GPU access → IOMMU fault → recovered by fault handler (attributed via memfree list). Design is internally consistent → **"GPU writes into recycled pages" requires a PTE-lifetime bug, not a refcount-lifetime bug.**
7. **kgsl_mmu_get_pt_from_ptname returns a pagetable WITHOUT kref** (vs kgsl_get_pagetable which does it right). Only caller: a4xx_preempt_token (Adreno 4xx preemption; internal ptname from PT_INFO) — NOT reachable on our a5xx GPU, not user-controlled. Latent hazard, filed.
8. **kgsl_mmu_put_gpuaddr**: on unmap failure keeps gpuaddr (avoids iommu BUG_ON on remap) — reasonable; no double-unmap seen.

## GPU-write theory status
The promising endgame remains: find a path where SMMU PTEs outlive the mem entry's page ownership (pagetable UAF, failed unmap, TLB deferral), then use Adreno MEM_WRITE packets through the stale mapping to write into recycled kernel memory — a kernel write that bypasses the hardened-usercopy wall entirely, chainable with our binder physmap READ (locate + verify targets).

## Dispatcher / context / pagetable lifetime audit (round 4 — verified against TARGET DISASM, not just source)
9. **adreno_dispatcher_queue_cmd**: disciplined — detached/invalid checks under drawctxt->lock (incl. after wait_event sleep), bounded queue, fault-policy inheritance. Clean.
10. **cmdbatch→context ref**: `kgsl_cmdbatch_create` takes `_kgsl_context_get` (atomic unless-zero) — every queued batch pins its context ✓.
11. **adreno_drawctxt_switch detach-guard**: PRESENT IN TARGET (disasm c05318d0: `ldr r3,[r2,#0x18]; tst r3,#2` = DETACHED bit check before pt-switch submit; `_kgsl_context_get` ldrex/strex loop; `new_pt = proc_priv->pagetable` at [r4+0x14]→[r3+0x3c]). The 15.1 comment ("pt destroyed before pt switch commands execute → pagefaults") documents the known race; guard is in our binary.
12. **kgsl_context_init proc_priv ref**: PRESENT IN TARGET (disasm c050f360: atomic ldrex/strex inc-unless-zero on proc_priv->refcount at c050f40c with cmp r12,#0 bail; context->proc_priv/dev_priv/tid stores; kgsl_sync_timeline_create call). The lifetime chain **batch→context→proc_priv→pagetable** is airtight against the naive stale-TTBR0 chain (last-fd-close while GPU in flight).
13. **Pt-switch mechanism confirmed** (adreno_iommu.c): GPU gets `CP_SMMU_TABLE_UPDATE(ttbr0, contextidr)` (a5xx path _adreno_iommu_set_pt_v2_a5xx) — raw TTBR write by the CP. Any exploitable variant must break the ref chain, not just race the submit.

**Round-4 verdict**: the cmdbatch-generation driver in OUR target already contains the known lifetime fixes (context refs on batches, detach-guard on pt-switch, proc_priv ref on contexts). The naive stale-pagetable chains are closed. Remaining unexplored surfaces: a5xx fault handler, issueibcmds/submit_commands parsers, setup_userbuf GUP pinning, event-group refcounts, perfcounter paths.

## Remaining audit queue (priority)
1. **kgsl_mmu.c pagetable refcounting** (attach/detach/create/put paths; kgsl_mmu.c lines 25-136 read: get/put pattern looks right so far; finish: kgsl_mmu_putpagetableobject, per-process pt lifecycle vs context teardown)
2. **adreno_dispatch.c**: submit/retire loop, cmdbatch lifetime vs context destroy (drawctxt_destroy racing in-flight batches — classic)
3. **adreno_a5xx.c** (124KB): pagefault handler, preemption-off paths, CP mechanism (our GPU!)
4. **kgsl_ioctl_rb_issueibcmds / submit_commands / timestamp_event priv copies** (user-structured input parsing, kgsl.c:1794/1833, 2176, 2215, 2754, 2861)
5. kgsl_sharedmem.c: kgsl_setup_userbuf (get_user_pages pin paths for map_user_mem)

## Banked verdicts on user-supplied references
- CVE-2021-28663 (lntrx): Mali-only, 64-bit — inapplicable; technique lens applied to kgsl lifecycle audit instead.
- CVE-2014-4014 (Rosanne-Luo): fixed in mainline ≥3.16 (we're 3.18.71) + requires unprivileged userns (Android 8.1 forbids). Dead two ways.
- CVE-2017-14491 (Rosanne-Luo): dnsmasq present but unreachable under no-reset red line; non-root payoff even then. Dead under constraints.
- CVE-2022-22077 (grisuno): MSI RTCore64.sys — Windows. Inapplicable.

---

## ROUND 5 (final): CONFIRMED VULNERABLE — CVE-2021-1905 in our binary

**kgsl pid-number reuse → cross-process private confusion → UAF** (May 2021 ASR, "UAF when handling memory mapping of multiple processes simultaneously", exploited in the wild).

**Binary proof** (kernel.elf, `kgsl_process_private_new` inlined in `kgsl_open` at c05104d0–c0510598):
- `c05104f0: ldr r8, [r3, #0x3cc]` — tgid NUMBER (task_tgid_nr inlined, offset matches our M2-banked tgid@+0x3CC)
- `c0510500: ldr r1, [r5, #0x4]` + `c0510504: cmp r1, r8` — `private->pid == tgid` NUMBER COMPARE on the process_list walk → match = inherit existing private (kref_get_unless_zero ldrex/strex at c0510530)
- `c0510598: str r8, [r9, #0x4]` — new private stores the bare number, zero struct-pid refs

**Fixes ABSENT from our binary** (both verified by commit diffs, codelinaro msm-3.18 LA.UM.7.7.c26):
- `93fde26e` (2021-01-11) "Compare pid pointer instead of TGID for a new process" — switches to struct pid pointer compare + get_pid/put_pid lifecycle (also adds put_pid in kgsl_destroy_process_private)
- `22ea8192` (2021-01-12) "Correct the refcount on current process PID" — comment: multiple pid refs per process struct "can lead to use-after-free"

**Exploit geometry** (every piece verified reachable from Termux uid 10042):
1. Process A opens /dev/kgsl-3d0 → private_A keyed by A's tgid NUMBER (pagetable_A + mem_idr)
2. A exits but its fd survives (fork-inherited or binder SCM_RIGHTS) → private_A persists
3. PID recycling: Android pid_max=32768 → fork/exit cycles recycle A's tgid number
4. New process C (recycled tgid) opens kgsl → number match → **C inherits private_A: A's GPU pagetable + memory entries**
5. Endgames: cross-process GPU memory access; pagetable/entry lifetime confusion with GPU in flight → stale-TTBR0 GPU-write chain (kernel write bypassing hardened usercopy); mem-entry double-free via confused idr ownership

**Also queued from the LA.UM.7.7 fix line (all postdate our kernel)**: e1996bd9 map_count NULL deref (2021), 3e624b77 OOB write in adreno_profile_submit_time (2021-09), fc0bdeb8 gpuaddr_in_range upper bound (2022), b7aa01f4 GUP cache flush (2022), 7a4e12ab user-address wraparound + b1277552 drawctxt switch error handling (2025).

## Round-5 additions to banked verdicts
- CVE-2023-20963 (Pinduoduo / framework PendingIntent): framework-level app privesc, not uid-0/kernel; 8.1 probably vulnerable but payoff wrong-shaped. Low priority.
- CVE-2021-1905: **PRESENT, VERIFIED, prime candidate** — pairs with the CVE-2019-2215 physmap read for locate+verify; the GPU-write endgame bypasses the hardened-usercopy wall that killed the binder endgame.
- CVE-2022-25720 (rate-set dup): in our qcacld-2.0 binary but writes bounded ≤12 → in-struct only; contained (verified in disasm). The 8devices IoT fork (security-fixed through 2026) + Motorola fork (2018-19) provide the full WLAN fix list; frame-triggered candidates triaged (limProcessDisassocFrame read, dot11f_unpack underflow reads, wma event OOB writes) — reads so far, writes only via FW-event paths.

## Audit method (reusable)
Device binaries extracted: kernel.elf (unstripped) + qca_cld_wlan.ko (unstripped, from rev5 vendor.bin via 7zz). Diff bases: codelinaro msm-3.18 LA.UM.7.7.c26 (final 3.18 LA line, security-fixed through 2025) for kernel drivers; 8devices/qcacld-2.0 IoT fork (2026) for the WLAN module. Fix commits enumerated via GitLab commits API with date+path filters (search= is broken on that instance).
