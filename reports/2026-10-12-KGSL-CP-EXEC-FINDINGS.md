# KGSL on-device findings — CP command execution + privileged-packet status (2026-10-12, session 7)

Target: RG3205W / msm8953 / Adreno 506 (a5xx) / kernel 3.18.71-perf armv7 /
no KASLR / SELinux enforcing. Access = untrusted_app uid 10042 (Termux).
Harness: `binder-exploit/kgsl-cp.c` (built from the proven `kgsl-probe.c`).

## Confirmed on-device

### 1. The a5xx CP executes user-submitted command streams (NEW, important)
A plain IB submitted through `KGSL_IOCTL_GPU_COMMAND` is executed by the CP:

```
[A ib]: 703d8003 00310000 00000000 11111111   # CP_MEM_WRITE(gpuaddr, 0x11111111)
[+] A plain CP_MEM_WRITE rc=0 errno=0 ts=1
    mark[0]=11111111 <<< GPU WROTE
```

⇒ We have a **GPU write primitive**: `CP_MEM_WRITE` writes attacker-controlled
32-bit words to any address the current SMMU page table maps. (This is a write
*by the GPU*, so it bypasses the arm32 hardened-usercopy wall entirely.)

### 2. `CP_SMMU_TABLE_UPDATE` from a plain IB is IGNORED (privileged-packet gate)
```
[C] plain-IB CP_SMMU_TABLE_UPDATE(TTBR0=0) then CP_MEM_WRITE 0x33333333
    mark[0]=33333333   # the MEM_WRITE ran, the SMMU update did NOT take effect
```
So we cannot set TTBR0 from a normal IB ⇒ no direct arbitrary-physical R/W via
the cheese (CVE-2025-21479) route.

### 3. Draw-state execution is deferred on a5xx (cheese bypass not available)
Built a5xx-format `CP_SET_DRAW_STATE` streams `(grp_id<<24)|(flags<<16)|dwords`
with every plausible flag (load-immediate 0x8, dirty 0x1, both, grp 1, and the
A730 modes<<20 layout). None executed the embedded `CP_MEM_WRITE`; the stream is
loaded for a *future draw*, not run immediately. The A730 microcode bug that
misclassifies SDS as RB does not manifest here.

## Source findings (target kgsl-src, cross-checked against vendor fixes)

- **`kgsl_sharedmem_find()` / `kgsl_sharedmem_find_id()` do NOT test
  `pending_free`** before `kgsl_mem_entry_get()` (`kgsl.c:1204`, `kgsl.c:1232`).
  Vendor fix `0a4ef64e3f` ("Return mementry only if pending_free is not set")
  adds exactly that check and is **absent** from our tree. This is a candidate
  UAF surface, and it compounds with CVE-2021-1905's shared private.
- `_insert_gpuaddr()` has `else BUG()` on duplicate base; `kgsl_iommu_set_svm_region()`
  overlap test (`gpuaddr + size <= start`) is wraparound-prone (later vendor
  fixes `fc0bdeb8`, `7a4e12ab` = "wrap around … use after free" are absent).
- Page-table memory is owned by the generic IOMMU (`iommu_domain_alloc`,
  `DOMAIN_ATTR_TTBR0`), not mmap-able ⇒ no direct PTE control from userspace.
- a5xx register protection (`a5xx_protect_init`) covers RBBM / CP (0x800,
  0x840, 0x880, 0xAA0) / RB / VPC / UCHE / **SMMU** ranges ⇒ no raw type4 write
  to a control register.

## Where this leaves the root paths

| path | status |
|---|---|
| cheese / `CP_SMMU_TABLE_UPDATE` arbitrary phys R/W | **blocked** on a5xx (plain IB ignored, draw-state deferred) |
| plain-IB GPU **write** to GPU-mapped memory | **works** (but only current page table) |
| CVE-2021-0920 af_unix UAF | race fires; reclaim can't win the free→read window |
| CVE-2021-1905 pid-reuse shared `process_private` | primitive **confirmed**; kernel-write endgame unresolved |
| CVE-2019-2215 binder | arbitrary **read** works |

## Recommended next step (highest EV now)

Drive the **CVE-2021-1905 shared-private into a `kgsl_mem_entry` UAF**, using the
missing `pending_free` guard as the concrete defect:

1. parent holds a vma ref on entry E (fork before the original dies);
2. recycled-tgid sibling shares the private and frees E (`GPUMEM_FREE_ID`) so the
   idr ref drops while a vma ref keeps E alive and `pending_free=1`;
3. re-find E via the unguarded `kgsl_sharedmem_find[_id]()` and take the path that
   assumes a live entry → free/reclaim E with controlled data;
4. hijack `entry->memdesc.ops->vmfault` and trigger it with a fault on the vma
   (`kgsl_gpumem_vm_fault` calls `entry->memdesc.ops->vmfault` — a controllable
   indirect call → the kernel-write/ROP primitive that bypasses usercopy).

Fallbacks if step 3 does not yield: SVM-region wraparound (`fc0bdeb8`/`7a4e12ab`),
or 1905 stale-SMMU via the GPU write primitive above.
