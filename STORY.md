# The story — every path we tried, kernel and off-kernel

This is the narrative record behind this repository: the goal, the ground rules,
the off-kernel device/cloud/application work, the kernel work, the dead ends, the
retractions, and where things stand. The distilled findings live in
[`reports/`](reports/); the raw session log lives in
[`reports/session-log/`](reports/session-log/); the code lives in
[`harnesses/`](harnesses/).

It is published because the *process* is as useful as the result: most of the
value here is in the negative results and the exact reasons each path closed.

---

## Target and access

| | |
|---|---|
| Device | ASKEY **RG3205W** "Movistar Home" smart speaker |
| SoC / GPU | Qualcomm **msm8953** (Snapdragon 625, 8×Cortex-A53), **Adreno 506** |
| OS | Android 8.1, **armv7** userspace, `ro.build.type=user`, `ro.debuggable=0` |
| Kernel | **3.18.71-perf**, **no KASLR** (base `0xC0008000`), SELinux **enforcing** |
| Attacker | `untrusted_app` `u0_a42` / uid 10042 (Termux), physical touch access |

The device is a carrier-managed TR-069/CWMP client with a Movistar/Troya
application stack on top.

## Ground rules (red lines)

These were fixed at the start and never crossed:

- **No flashing, no USB, no EDL, no OTA/recovery, no factory reset.** Software
  only, over the network / from the app sandbox.
- **No persistence hacks, no bricking.** A panic costs ~15 min and requires
  manually restarting the Termux poller on the device.
- The work is authorized on the owner's own device. See [`LICENSE`](LICENSE).

## How the work was done

The device runs a Termux **poller** that fetches `job.sh` from a local HTTP server
every ~15 s, downloads a gzipped binary, checks its md5, runs it, and uploads the
output. Quarantined or device-downing binaries were deliberately kept unservable
until they were safe by construction. All harnesses are in
[`harnesses/`](harnesses/).

---

## Part A — Off-kernel (device, cloud, applications)

The motivating idea: a carrier device ships privileged **SYSTEM** apps and an
ACS-managed config plane. If we can drive those, we never need a kernel bug.

### What was found (all reachable from uid 10042)

- **Unprotected broadcast control of the SYSTEM TR-069 app**
  (`/system/priv-app/AskeyTR69`, `sharedUserId=android.uid.system`,
  `debuggable=true`). Its receiver checks no permission for several actions:
  - `askey.tr069.intent.action.getcfg` → broadcasts the **entire CWMP config**
    as JSON (ManagementServer URL/username/password, ConnectionRequest creds,
    ACS cert, service JWTs).
  - `askey.tr069.intent.action.testurl` → **rewrites the ACS URL** (we pointed it
    at the tester host).
  - `askey.tr069.intent.action.setcfg` → **arbitrary config write as SYSTEM**
    (verified by rewriting `Device.LAN.*` and the DNS server).
  - `askey.socket.intent.action.aspsh` → SYSTEM `commandProcess()` (fixed
    dispatcher only, no arbitrary exec).
- **ACS impersonation is trivial**: the app's `checkServerTrusted()` is a no-op
  and it accepts any TLS certificate; we ran a fake ACS/CWMP server.
- **The updater** (`com.telefonica.movistarhome.updater`, SYSTEM,
  `INSTALL_PACKAGES`+`DELETE_PACKAGES`+`REBOOT`) exposes an unprotected dynamic
  receiver `ACTION_UPDATE_APPS` → `silentInstallPackage()` →
  **silent APK install as SYSTEM**, and `ACTION_UPDATE_FIRMWARE` → recovery OTA
  (a red line — never used).
- The ROM is **test-keys**; an AOSP `platform` signing key was obtained, so a
  platform-signed APK with `sharedUserId=android.uid.system` could be built and
  installed by the silent-install path.
- **Troya apps trust any TLS cert** and take their backend URL from
  `/data/movistarhome/environments.json` (mode `0771 system:system`).
- **DNS/clock control**: `Device.LAN.AddressingType=static` +
  `DNSServers=<tester>` moved the device resolver to us; the overly helpful
  **1970 clock** (no SNTP on the LAN) turned out to be the root cause of a whole
  night of "the updater never runs" — its boot/auth chain dies on a 1970 clock.

### Why it stopped

The chain needed **one privileged app to act on attacker input**:

- The updater's silent-install receiver is **dynamic** (registered in
  `PackageService.onCreate`), and getting that service to run and reach its
  backend was never achieved.
- The backend hostname wasn't in the DNS-hijack suffix list, and
  `/data/movistarhome/environments.json` wasn't writable from the sandbox.
- Every other reachable SYSTEM sink was either a **fixed dispatcher**,
  **signature-gated**, or boot-triggered only.

Everything else was built and verified server-side; the verdict was recorded as
**off-kernel chain closed on the "privileged app action" step** (see
`reports/session-log/2026-10-12-OFFKERNEL-VERDICT-CLOSED.md`).

---

## Part B — Kernel: the two hard facts

### B1. The usercopy wall (why most kernel-write exploits are dead here)

arm32 hardened usercopy on this kernel compiles **stores to userland as
user-mode accesses**:

- `copy_page_to_iter` emits `STRBT` (`e4c83000`, P=0/W=0 — "as if user mode").
- `arm_copy_to_user`/`__copy_to_user_std` are `strt`-based: every copy-out byte
  is a user-mode store.

Kernel pages deny user-mode access, so **any copy-*to*-user whose destination is
a kernel address faults and is refused** — regardless of `addr_limit` or any
range check (the gate is the hardware access permission, below any check).

Consequence, proven live: the CVE-2019-2215 write family (self-overwrite via a
redirected `iov_base`, `addr_limit` clobber, cred/`selinux_enforcing`/
`modprobe_path` patches) is **categorically impossible** on this kernel. Copy
**-in** uses privileged loads, so reads still work.

> **The only viable kernel-write path is the GPU/SMMU**: Adreno command streams
> are translated by the IOMMU and written by the hardware CP — no usercopy, no
> `access_ok`, no AP check.

### B2. No KASLR, and a reliable arbitrary read

No KASLR means fixed global addresses (`init_cred`, `commit_creds`,
`selinux_enforcing`, `modprobe_path`, …).

**CVE-2019-2215 (binder)** is present and gives a **reliable arbitrary physical
memory read** via the `EPOLL_CTL_ADD`/`BINDER_THREAD_EXIT` race → physmap. It is
the *locate + verify* oracle for everything else (20+ clean runs; task/cred/
binder offsets verified). The write direction is walled by B1.

---

## Part C — KGSL (Adreno) — the write path

`/dev/kgsl-3d0` is world-writable and the whole 34-ioctl surface is callable.

### C1. The initial candidate: pid-number → `kgsl_process_private` reuse

`kgsl_process_private_new()` keyed the process by a **bare `tgid` number** with a
plain `==` compare and no `struct pid` reference. A recycled tgid inherits a dead
process's kgsl private (pagetable + `mem_idr`). The upstream fixes
(`93fde26e` compare-`struct pid`, `22ea8192` pid refcount) are **absent** from
this binary. This was proven to inherit deterministically on-device.

However, the audit also showed the modern lifetime guards *are* present in this
tree (batches pin their context, pt-switch has a detach guard, contexts pin
`proc_priv`), so the naive "stale page table + GPU write" chain was closed. The
exact UAF endgame stayed elusive.

### C2. The real bug we could see: CVE-2021-1905 SVM `gpuaddr` sharing

The upstream fixes for CVE-2021-1905 are two commits (the Android "KGSL" patch
series):

- **Patch #1 `d6770f2b86b6`** — removes the single shared `memdesc->useraddr` /
  `mapsize` used as the "is it mapped / by whom" identity, and replaces it with an
  `atomic_t map_count`; adds a `check_vma()` that **rejects importing a vma that
  KGSL itself owns**.
- **Patch #2 `be897e2fa155`** — adds a `memdesc->lock` and
  `if (memdesc->gpuaddr) return -EBUSY;` to `_gpu_set_svm_region()`, "**to prevent
  multiple vmas from trying to map a SVM region at the same time**".

We decompiled the device's `_gpu_set_svm_region`, `kgsl_mmu_map`,
`kgsl_mmu_put_gpuaddr`, `kgsl_mmu_unmap`, etc. from the shipped kernel and
confirmed the vulnerable shapes.

### C3. The double-region and the falsified stale-PTE

A deterministic single-process trigger exists: `mmap` → `mremap`-shrink (which
resets the shared `useraddr` to 0 via the tail `vm_close` while the head vma still
maps) → `mmap` again. This re-assigns `memdesc->gpuaddr` from **G1** to **G2**.

We initially believed G1's SMMU PTE survived this ("stale PTE"), which would have
been a direct GPU-write primitive. **That was wrong**, and we corrected it in
public:

- `harnesses/kgsl-faulttest.c` proved a GPU write to an **unmapped** `gpuaddr` is
  **non-fatal** (the marker still retires). Marker-liveness is therefore **not** a
  mapping test, and an earlier "PTE survives" result was invalid.
- `harnesses/kgsl-g1map.c` used a **value-based** staged test (write region, read
  the CPU alias) and showed G1 is genuinely **unmapped** by the second
  `_gpu_set_svm_region`. See
  [`reports/2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md`](reports/2026-10-13-KGSL-SESSION10-G1-NOT-MAPPED.md).

### C4. A real, deterministic primitive: the "zombie" remap

`harnesses/kgsl-dblcheck.c` showed that after the double-map, the object can be
**freed (`GPUOBJ_FREE`) while vmas still hold references, and then re-mapped** —
a freed/pending `kgsl_mem_entry` that remains CPU- and GPU-mappable. `find_id`
still resolves it; `mremap`-shrink zeroed `useraddr`, so `get_mmap_entry` happily
maps it again. The `pending_free` flag is only a diagnostic (`memfree.list` is
not a protection).

This is the CVE-2021-1905 facilitator: mapping/lifetime identity is a single
shared `useraddr`.

### C5. The race (patch #2's actual target)

Because `mmap_sem` serialises same-`mm` maps, patch #2's "multiple vmas at the
same time" is the **fork + inherited kgsl fd** case: two processes share one
`kgsl_process_private` (and thus one `memdesc`/pagetable) in **different `mm`s**,
so they can run `_gpu_set_svm_region` truly concurrently. Two regions can then be
mapped while only one is tracked by `memdesc->gpuaddr`; the other is orphaned and
survives `free()`.

`harnesses/kgsl-race.c` is the two-process race probe. Current status: built and
being iterated (see the session log).

### C6. Other KGSL items triaged

- **`3e624b77` profiling OOB write** — present, reachable, but the overrun lands in
  the vmap guard page → DoS, not a neighbour write. Retired.
- **SVM region wrap-around (`7a4e12ab`, 2025)** — the old rbtree bookkeeping has
  no `end <= gpuaddr` guard; the region insert accepted oversized input but the
  follow-up import cleaned up. The wrap effect is confined to the allocator math;
  not yet turned into an overlap.

---

## Part D — Other CVEs triaged

| CVE / bug | Verdict on this device |
|---|---|
| **CVE-2019-2215** binder | **Present**; arbitrary physmap **read** works; write walled (B1) |
| **CVE-2021-0920** af_unix GC/MsgPeek | **Present** (fix `cbcf01128d0a` absent); textbook UAF, race-gated; a mature public exploit exists for the same interaction (x86_64, not portable). Planned port; not yet executed |
| **CVE-2021-1905** kgsl | **Present**; current primary kernel path (Part C) |
| `3e624b77` kgsl profiling | Present, reachable, guard-limited — retired |
| CVE-2020-0041 binder | **Absent** (pre-`bde4a19f` pointer binder) |
| CVE-2021-1048 epoll | N/A (needs 5.9-era `f_tfile_llink`) |
| CVE-2017-6074 DCCP / CVE-2018-9568 RDS | Fixed / stub only |
| CVE-2021-28663 Mali, CVE-2014-4014 userns, CVE-2017-14491 dnsmasq, CVE-2022-22077 MSI | Inapplicable or red-lined |

---

## Timeline (condensed)

| When | What |
|---|---|
| s1–s4 | Off-kernel recon: TR-069 app control, ACS impersonation, config read/write, updater silent-install identification |
| s4–s5 | CVE census against the shipped kernel; CVE-2019-2215 read proven; `3e624b77` reachability |
| s5 | **usercopy wall** proven (copy-out is user-mode `STRBT`); binder write family closed; af_unix-0920 identified + GPZ lead |
| s6 | Kernel pivot to KGSL; pid-reuse inheritance proven; SVM wrap probe |
| s7 | Off-kernel final push: DNS/NTP hijack, fake Troya backend, platform-signed APK, silent-install blocker; **1970-clock root cause**; off-kernel chain closed |
| s8 | KGSL SVM double-region; patch #2 deterministic trigger; CP writes proven; CP-exec findings |
| s9 | Pending-free / pool reclaim attempts; "stale PTE" hypothesis (later retracted) |
| s10 | **Correction:** unmapped GPU writes are non-fatal; G1 is unmapped by the second region; stale-PTE premise falsified |
| s11 | "Zombie" freed-entry remap; exact patch #1/#2 diffs; two-process race path (current) |

## Corrections and retractions (kept on purpose)

Good research records its mistakes. These were wrong and are retracted in the
reports:

- "Arbitrary kernel write proven" (M3/M4) — the full-`readv`-count signal was
  circular.
- "No PAN/uaccess gate in the copyout path" — wrong; the gate is the hardware
  access permission on the user-mode store (`STRBT`).
- "The stale SVM PTE survives `free()`" — wrong; see Part C3.
- "SVM writes never land" — a probe artifact (reusing the async command buffer
  without polling the marker). Fixed by object-write + marker in one IB.

## Current status

- Kernel: `CVE-2021-1905` remains the primary path; the live thread is the
  **two-process SVM map race** (Part C5) and converting the zombie/orphaned
  mapping into a reclaimed-page GPU write, verified with the CVE-2019-2215 read.
- Off-kernel: closed on the "privileged app action" step.
- The device is healthy; all probes are safe-by-default.
- `init_cred`-style patches are explicitly *not* persistence and do nothing for
  SELinux; that is stated up front wherever root lands.

## Credits

See [`CREDITS.md`](CREDITS.md). This work leans heavily on public prior art:
Project Zero (Jann Horn) and the CVE-2019-2215 PoCs (wired0ut, LIznzn, kangtastic),
Maddie Stone's in-the-wild write-ups, the upstream/vendor commits named above, and
the community device research in
[`zry98/movistar-home-hacks`](https://github.com/zry98/movistar-home-hacks).
