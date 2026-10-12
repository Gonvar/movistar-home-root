# KGSL / CVE-2021-1905 — MSM8953 (armv7) research notes

Device-side security research on the Qualcomm Adreno (KGSL) driver shipped in the
**ASKEY RG3205W** ("Movistar Home" smart speaker), an **armv7 / ARM32** device:

| | |
|---|---|
| SoC | Qualcomm **MSM8953** (Snapdragon 625) |
| GPU | **Adreno 506** (a5xx) |
| Kernel | **3.18.71-perf**, armv7l, **no KASLR** |
| Userspace | Android 8.1, **SELinux enforcing** |
| Attacker | `untrusted_app`, uid 10042 (Termux), `/dev/kgsl-3d0` reachable |

This repo documents a **from-scratch re-derivation** of the KGSL SVM
use-after-free behind **CVE-2021-1905** (a.k.a. the `_gpu_set_svm_region()`
double-region bug), what was proven on the physical device, the exact
obstacles that remain, and the tooling used to get there.

> **Status: partial primitive, not a full exploit.** We have a deterministic,
> race-free trigger and a *stale GPU page-table entry* that survives the free of
> the owning object. Turning that into a kernel read/write is still open; the
> current wall is reliable **physical-page reclaim** of the freed KGSL pages.

---

## TL;DR of the bug

`_gpu_set_svm_region()` (KGSL SVM / `KGSL_MEMFLAGS_USE_CPU_MAP`) maps an entry's
pages at a GPU virtual address derived from the CPU mapping and stores it in the
single shared `memdesc->gpuaddr` / `memdesc->useraddr` fields. A single
`kgsl_mem_entry`'s memdesc can be mapped by more than one vma/process, so:

1. allocate an SVM entry;
2. `mmap` it → region **G1** registered + mapped, `useraddr = G1`;
3. `mremap(..., shrink)` → the tail `vm_close` resets the **single shared**
   `useraddr` to `0` while the head vma keeps the entry alive;
4. `mmap` it again → `_gpu_set_svm_region()` runs a **second time** and
   re-assigns `memdesc->gpuaddr = G2`, leaving **G1 registered and GPU-mapped
   but no longer tracked** by the entry.

**Device result (session 10): the second `_gpu_set_svm_region` tears G1 down.**
The entry ends up tracking `G2` only, and there is **no orphaned/stale GPU
mapping** (see [`reports/2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md`](reports/2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md)).
The obvious stale-PTE primitive therefore does **not** exist in this tree; the
open work is to find the actual exploitable consequence of the shared
`gpuaddr`/`useraddr` (see the report's candidate directions).

The Google fix is two patches (see [`reference/upstream-commits.md`](reference/upstream-commits.md)):

* **#1** — remove `memdesc->useraddr` / `mapsize`; track mappings with
  `atomic_t map_count` + a `check_vma(hostptr, size)` walk.
* **#2** — lock `_gpu_set_svm_region()` and return `-EBUSY` if `gpuaddr` is
  already set. Our device runs a tree that predates both.

NVD: *"Possible use after free due to improper handling of memory mapping of
multiple processes simultaneously."*

---

## What was proven on the device

Consolidated from [`reports/`](reports/) (all reproduced under
`untrusted_app`, no panic, CP alive after every run):

* **`kgsl_sharedmem_find()` / `find_id()` hand out `pending_free` entries** —
  the 2017 guard `0a4ef64e3f` is absent. Facilitator, not the main bug.
  ([`reports/2026-10-12-KGSL-PENDING-FREE-RESULTS.md`](reports/2026-10-12-KGSL-PENDING-FREE-RESULTS.md))
* **Resurrection into a second vma** — after `mremap`-shrink resets the shared
  `useraddr`, a second `mmap` re-publishes a `pending_free` entry through both
  the `find(gpuaddr)` and `find_id` paths.
* **Race-free double SVM region** (`kgsl-svmdbl`): `gpuaddr` is re-assigned
  `G1 → G2` deterministically; the patch #2 check would have returned `-EBUSY`.
* **SVM GPU writes are real and CPU-coherent** (`kgsl-svmsize`, `kgsl-svmcp`):
  `CP_MEM_WRITE` to a single SVM `gpuaddr` lands in the CPU mapping, for 1- and
  2-page entries, primed or not.
* **SVM GPU writes are value-coherent** (`kgsl-svmsize`, `kgsl-g1map`): a
  `CP_MEM_WRITE` to an SVM `gpuaddr` is observable in the CPU alias, so
  mapping can be tested by **value**, not by marker liveness.
* **G1 maps after `mmap`#1 and after the shrink, but is unmapped by the second
  `_gpu_set_svm_region`** (`kgsl-g1map` s0/s1/s2/s3). This falsifies the
  stale-PTE premise.
* **GPU translation faults are non-fatal** (`kgsl-faulttest`): an IB writing an
  unmapped `gpuaddr` and then a marker still retires the marker. Marker
  liveness alone is therefore **not** a mapping test.

## The open problem

Earlier reclaim attempts (`kgsl-poolreclaim`, `kgsl-reclaim`: 8192 × 4 KiB KGSL
allocations + a 256 MiB anon spray) found no hit — but, per the correction above,
they were not measuring a mapping because G1 has none. Producing a **genuine
dangling GPU mapping** (or a freed `kgsl_mem_entry` reachable via a live vma) is
the current focus; the CVE-2019-2215 arbitrary physmap read remains available as
the locate/verify oracle.

---

## Harnesses

All under [`harnesses/`](harnesses/); arm32 static, built with `zig cc`
(see [`harnesses/build.sh`](harnesses/build.sh)). They are deliberately
observational / safe-by-default, and each prints a `[n] step …` trace.

| harness | question it answers |
|---|---|
| `kgsl-pend.c` | does `GET_INFO`/`find` return a `pending_free` entry? |
| `kgsl-pend2.c` | can `mremap`-shrink + 2nd `mmap` resurrect it? |
| `kgsl-svmdbl.c` | deterministic double SVM region (`G1`→`G2` re-assign) |
| `kgsl-svmcp.c` | is one SVM `gpuaddr` CP-writable? |
| `kgsl-svmdual.c` | do `G1`/`G2` alias? does the CP survive? |
| `kgsl-svmsize.c` | size / priming / single-IB controls for SVM writes |
| `kgsl-svmstale.c` | stale-`G1` write attempt (older, superseded) |
| `kgsl-stalelive.c` | (marker-based) G1 liveness after free + reclaim scan — **superseded** |
| `kgsl-g1map.c` | staged **value-based** G1/G2 mapping test (decisive) |
| `kgsl-faulttest.c` | is a CP write to an unmapped `gpuaddr` fatal? (it is not) |
| `kgsl-reclaim.c` | paired-submit kgsl + anon reclaim drain |
| `kgsl-poolreclaim.c` | FIFO page-pool drain (self-verifying, batched) |
| `kgsl-cp.c`, `kgsl-probe.c`, `kgsl-svm{,2,3}.c`, `kgsl-1905*.c` | reachability / CP / SVM scaffolding |
| `poc-ro.c` | CVE-2019-2215 arbitrary physmap read (locate/verify oracle) |

### Method-correction worth reading

Several early negative results were **probe artifacts**, not kernel behaviour:
calling a `CP_MEM_WRITE` helper twice reuses the same mapped command buffer
while the first *asynchronous* `GPU_COMMAND` batch may still be executing, so the
second call silently overwrites the first batch. The fix — emit the object write
and a marker **in one IB** and **poll the marker** before reusing the buffer —
is implemented in `kgsl-stalelive.c` / `kgsl-svmsize.c`. This single change
turned "SVM writes never land" into "all SVM writes land".

---

## Community / reproduction resources

The community project for this exact device is
**[`zry98/movistar-home-hacks`](https://github.com/zry98/movistar-home-hacks)**
(same RG3205W, Snapdragon 625, Android 8.1, kernel 3.18.71-perf armv7):
disassembly, **EDL mode**, a working `firehose.mbn`, bootloader unlock, stock ROM
dumps and a custom ROM. Use it to obtain the shipped `boot`/`system`/`vendor`
images (our analysis runs against the shipped kernel) and as a recovery path.
See [`CREDITS.md`](CREDITS.md) for the full list of community contributors.

## Credits

See [`CREDITS.md`](CREDITS.md). This work builds directly on the public patches
and prior-art PoCs listed there. The "original repo" this research indexed first
is [`TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664`](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664),
and the device community reference is
[`zry98/movistar-home-hacks`](https://github.com/zry98/movistar-home-hacks).

## Legal / ethics

Provided for defensive research, education, and interoperability on hardware you
own. See [`LICENSE`](LICENSE). Do not use against devices you are not authorised
to test.
