# kgsl profiling path — REACHABLE, write PROVEN (2026-10-11, session 5)

**Status: the `3e624b77` OOB-write code path is proven reachable from Termux
untrusted_app, and the kernel profiling write executed into a buffer we control.**
Device healthy afterwards (still polling). Evidence:
`reports/evidence/kgsl-profile-reachable-output.txt`.

## What was proven

The full chain runs as uid 10042 (untrusted_app), no extra permissions:

```
open /dev/kgsl-3d0                                   OK
GETPROP(VERSION)        -> drv 3.14 dev 3.1          OK
GETPROP(DEVICE_INFO)    -> chip_id=0x05000600 ...    OK   (Adreno 506, a5xx)
GPUMEM_ALLOC_ID(0x10000)-> id=1 gpuaddr=0x300000     OK
mmap(id<<12)            -> user mapping              OK
DRAWCTXT_CREATE         -> drawctxt_id=9             OK
GPU_COMMAND(profiling MARKER, 1 PROFILE obj)         rc=0  (no write: SW-retired)
GPU_COMMAND(profiling SYNC,   1 PROFILE obj)         rc=0  (no write: SW-retired)
GPU_COMMAND(profiling REAL, 1x NOP IB, 1 PROFILE obj) rc=0
   readback @profile+0x8000:
     wall_clock_s=4599 ns=955289708 q=37846 sub=38205 ret=38239   <-- written
```

The profiling struct (`struct kgsl_cmdbatch_profiling_buffer`, 40 B) was
CPU-written by `adreno_ringbuffer_issueibcmds()` into our GPU buffer at the
address computed by `add_profiling_buffer()`. That is exactly the location of
the `3e624b77` bug.

## The pieces (all verified against target disasm + source)

1. **`add_profiling_buffer()` is reached via the objlist** of
   `KGSL_IOCTL_GPU_COMMAND` (0x4A): `kgsl_cmdbatch_add_memlist()` →
   `if (obj.flags & KGSL_OBJLIST_PROFILE) add_profiling_buffer(...)`, with
   `obj.{gpuaddr,size,id,offset}` all user-controlled.
2. **The profiling write only happens for a real cmdbatch.** MARKER cmdbatches
   (`!(flags&SYNC) && numcmds==0` → auto-marker) and SYNC cmdbatches are both
   retired in software (`_retire_marker` / `_expire_markers`), never reaching
   `adreno_ringbuffer_issueibcmds()`. Confirmed empirically (no write).
3. **A real cmdbatch needs a valid IB.** `_ringbuffer_verify_ib()` requires
   `ib->size != 0 && (size>>2) <= 0xFFFFF` and
   `kgsl_mmu_gpuaddr_in_range(pagetable, ib->gpuaddr)`. A zero-size IB returns
   `-EINVAL` (observed).
   - Minimal valid IB used: one **Adreno type-7 CP_NOP** packet.
     `ADRENO_LEGACY_PM4 = (rev < 500)` ⇒ a5xx is type-7;
     `cp_type7_packet(CP_NOP=0x10, cnt=1)` = `0x70100001`, + 1 payload dword.
     Harmless: the CP executes a NOP and retires.
4. **Context must request `PREAMBLE|NO_GMEM_ALLOC`** (`0x12`) — legacy context
   switch is rejected (`legacy context switch not supported` → EINVAL).
5. **The 3e624b77 fix is absent** (prior audit): `add_profiling_buffer.part.2`
   @ c051c268 does `kgsl_gpuaddr_in_memdesc(gpuaddr,size)` once and then
   `profiling_buffer_gpuaddr = memdesc.gpuaddr + offset` with **no
   struct-size bound** — the vulnerable shape.

## OOB trigger geometry (next step)

**UPDATE — the overrun to open air is a guard page, not a neighbour (code-derived, high confidence).**

- `kgsl_allocate_user()` → `kgsl_sharedmem_page_alloc_user()` →
  `memdesc->ops = &kgsl_page_alloc_ops`, whose `.map_kernel` is
  `kgsl_page_alloc_map_kernel()` → **`vmap(pages, page_count, VM_IOREMAP, ...)`**.
  So a normal app GPU buffer's `hostptr` lives in the vmalloc area.
- `__get_vm_area_node` (disasm c0210088): `tst r6,#0x40` / `addeq r5,r5,#4096` —
  a 1-page guard is added unless flags has `VM_NO_GUARD (0x40)`. `vmap` passes
  `VM_IOREMAP (0x01)`, so **the guard IS added**.
- `kgsl_gpuaddr_to_vaddr()` bounds the CPU write to `[hostptr, hostptr+memdesc.size)`.
  For a page-aligned allocation (`memdesc.size == page_count*4096`), `offset` can
  reach `size-1`, so the 40-byte struct write lands in the guard page
  (`hostptr+size .. hostptr+size+39`) → **kernel page fault / oops** — a DoS, not
  a clean adjacent-object write. For a non-page-aligned size the overrun just sits
  in the vmap slack (harmless).
- Userspace has **no** GPUMEM_ALLOC flag to select the direct-map heap
  (`kgsl_sharedmem_alloc_contig` / dma_alloc is only used for kernel buffers, or
  when `KGSL_MMU_TYPE_NONE`).

So `3e624b77` on this device is a **reachable kernel-fault (DoS) primitive**, and
only a fragile situational write if a direct-map heap could be forced. The GPU-side
profiling writes (`gpu_ticks_submitted/retired` via REG_TO_MEM) do use the raw GPU
address unbounded, but that lands in GPU/SMMU space (another GPU mapping), not
kernel memory. **Net: de-prioritise `3e624b77` as a root primitive.**

The two UAF candidates (CVE-2021-1905 kgsl pid-reuse, CVE-2021-0920 af_unix) are
now clearly the better root paths.

## Artifacts

- Probe source: `binder-exploit/kgsl-probe.c`
- Built: `kgsl-probe.gz` (md5 changes per revision; r5 = `37f032c37f5cd0af40ea301dffe7c82b`)
- Runner: `job.sh` (JOB-89). Safe/repeatable: profile address stays in-bounds.
- Output: `reports/evidence/kgsl-profile-reachable-output.txt`

## Why this matters

The hardening `usercopy` wall that killed every binder write path does **not**
apply here — this is a direct CPU write into a GPU memdesc's kernel mapping. It
is a **race-free** primitive (no pid-recycle, no MSG_PEEK timing), reachable with
7 ioctls from an ordinary app. It now joins the shortlist as a live, proven
write primitive alongside CVE-2021-1905 (pid-reuse UAF) and CVE-2021-0920
(af_unix UAF).
