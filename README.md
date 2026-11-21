<div align="center">

# Rooting the Movistar Home (ASKEY RG3205W) — CVE‑2021‑1905 KGSL → uid 0 on MSM8953 / armv7

**A from‑scratch, hardware‑verified ARM32 exploit chain that takes an unprivileged Android app to `uid 0` on the ASKEY RG3205W “Movistar Home” smart speaker — with a full write‑up of *how* and *why* every step works.**

`Qualcomm Adreno KGSL` · `CVE-2021-1905` · `MSM8953 / Snapdragon 625` · `armv7l` · `Linux 3.18` · `Android 8.1` · `kernel read/write` · `privilege escalation` · `no KASLR`

</div>

---

## What this is

A complete, reproducible guide to exploiting a **use‑after‑free in the Qualcomm Adreno (KGSL) driver** on a 32‑bit Android 8.1 device, turning it into **arbitrary kernel read/write** and finally **`uid 0`** — plus the tooling and hard‑won pitfalls (device wedges, stochastic panics, SELinux/property dead ends) that nobody writes down.

If you are here because you are **trying to root an MSM8953 / Adreno 5xx device on Linux 3.18**, or you want to understand **how a real forged‑PTE kernel R/W primitive is built**, this is written for you.

> **Status: `uid 0` achieved, root shell proven, panics fixed — and now durable.** The chain is
> finished and verified on hardware. The six teardown panics that stalled it came from an
> over‑engineered ownership proof — not from the primitive — and the rule that fixed it is in
> [GUIDE §9](GUIDE.md#9-the-panics--solved-and-what-actually-caused-them). Root now **returns by
> itself ~2 minutes after every power cycle** (BootKeeper + a self‑driving agent), verified on
> hardware across a power cycle — [DURABLE-ROOT.md](DURABLE-ROOT.md) — and the box can be
> repurposed as a small operator appliance: [APPLIANCE.md](APPLIANCE.md).

## The target

| | |
|---|---|
| Device | **ASKEY RG3205W** — “Movistar Home” smart speaker |
| SoC / GPU | Qualcomm **MSM8953** (Snapdragon 625) / **Adreno 506** (a5xx) |
| Kernel | **3.18.71‑perf**, armv7l, **no KASLR**, `PHYS_OFFSET = 0x40000000` |
| Userspace | **Android 8.1.0** (SDK 27), SELinux **enforcing**, bootloader unlocked, `verity` enforcing |
| Attack surface | `untrusted_app` (uid 10042, a normal app) with `/dev/kgsl‑3d0` reachable |

## The chain in one picture

```
untrusted app  ──kgsl ioctls──▶  KGSL SVM region use‑after‑free (CVE‑2021‑1905)
        │
        ├─▶ reclaim a freed page as a PAGE‑TABLE (PTE) page we still map
        ├─▶ PROVE it is ours (spray signature + a software‑PTE‑only mincore flip)
        ├─▶ forge a user L2 descriptor → map a KERNEL physical page into our VMA
        ├─▶ arbitrary KERNEL READ/WRITE
        │        ├─ clear selinux_enforcing
        │        └─ resolve `current` via the runqueue; cred = real_cred = init_cred → uid 0
        └─▶ self‑alias our PTE page, zero every forged entry (safe teardown),
            fork a detached worker → `/system/bin/sh` running as uid 0
```

## Quickstart

```bash
# 1. build the harness (armv7, static musl)
cd exploit && ./build.sh          # produces ./kgsl-forge

# 2. push it to the device (Termux) and run it
#    (see tools/ for the hands-free HTTP poller workflow used in development)
./kgsl-forge
```

Success looks like:

```
[5.0] ci=274 e0=0x4bc4e7df -> owner region 400
[ROOT] uid 0 achieved
[AL] disarmed 7/7 slots (4,5,6,231,236,248,7)
[AL] root worker pid=3063   [AL] worker ALIVE status=0x0   [AL] worker state=S
[WK] calling execve(/system/bin/sh)
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

Step‑by‑step, including the *why* of every offset and flag → **[GUIDE.md](GUIDE.md)**.

## Contents

| Doc | What's inside |
|---|---|
| **[GUIDE.md](GUIDE.md)** | The whole workflow end‑to‑end: the bug, the primitive, the root, the shell, the pitfalls, the dead ends |
| **[DURABLE-ROOT.md](DURABLE-ROOT.md)** | Making root survive reboots: the seccomp wall, BootKeeper, the self‑driving agent chain, the doors |
| **[APPLIANCE.md](APPLIANCE.md)** | After the root: the reversible strip, a from‑scratch launcher, the dead‑RTC clock fix, AdGuard Home DNS |
| [chain/](chain/) | Sources for the durable boot chain (BootKeeper app, MH‑Agent, the box boot scripts) |
| [appliance/](appliance/) | The box's own software: launcher + operator tools + `device-tools/` |
| [exploit/](exploit/) | The working harness (`kgsl-forge.c`) + build script |
| [tools/](tools/) | The hands‑free on‑device iteration loop (host server, poller, job) |
| [reference/](reference/) | KGSL UAPI header, the upstream fix commits, and [`adbd-disabled.md`](reference/adbd-disabled.md) — why this box has no `adb` at all |
| [CREDITS.md](CREDITS.md) | Prior art and acknowledgements |

## Why it's interesting

- **CVE‑2021‑1905 is a known bug, but a working public *ARM32* chain is rare.** This documents the full exploitation path on 32‑bit, including the PTE‑encoding and cache‑coherency details that differ from the common arm64 write‑ups.
- **It shows the unglamorous 90%:** the "store wall", the self‑alias disarm, the driver wedge that forces a reboot per run, and the app‑level traps (seccomp killing your shell, `umask` hiding your output) that turn a working primitive into a *usable* root.
- **Everything here ran on physical hardware**, not an emulator — including the panics.

## Responsible use

This is **security research on my own device**, published so others can learn. It targets a specific, years‑old, end‑of‑life consumer device and a patched kernel bug. Don't point it at hardware you don't own.

## License

See [LICENSE](LICENSE).

<sub>Keywords: CVE-2021-1905, KGSL, Adreno, MSM8953, Snapdragon 625, RG3205W, Movistar Home, Android 8.1 exploit, armv7 root, kernel R/W, privileged escalation, patched PTE, page table forgery, durable root, Android boot persistence, BootKeeper, adb over WiFi, Android rooting guide.</sub>
