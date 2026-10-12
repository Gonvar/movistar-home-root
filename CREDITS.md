# Credits & prior art

This research stands on a lot of public work. If you are one of the people below
and want your entry changed or removed, open an issue.

## Original reference repo ("og repo")

* **TAKIANFIF** — [`CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664`](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664)
  — the "Qualcomm GPU / ARM Mali GPU" reference index that seeded this line of
  investigation.

## The actual CVE-2021-1905 fixes (patches)

Located via commit search; applied in the OnePlus SM8150 tree:

* **Patch #1** `d6770f2b86b6` — *"Apply google patch CVE-2021-1905_1 KGSL"*
  — committed by **hengyir.guo@oneplus.com**.
* **Patch #2** `be897e2fa155` — *"Apply google patch CVE-2021-1905_2 KGSL"*
  — committed by **mayuwu@wingtech.com**.
* Repo: [`Hikari-no-Tenshi/android_kernel_oneplus_sm8150`](https://github.com/Hikari-no-Tenshi/android_kernel_oneplus_sm8150).

The underlying patch content originates from **Google** (Android security);
CVE-2021-1905/-1906 were disclosed in the **May 2021 Android Security Bulletin**
and attributed to **Qualcomm**. Google noted limited, targeted in-the-wild
exploitation.

## Community device research — `zry98/movistar-home-hacks`

The reference community project for the **ASKEY RG3205W** itself (same SoC,
Android 8.1, kernel 3.18.71-perf armv7): disassembly, EDL mode,
**`firehose.mbn`**, bootloader unlock, stock ROM dumps and a custom ROM.
Invaluable for anyone reproducing this research (obtaining the shipped kernel,
boot/vendor partitions, and a recovery path after a bad run).

* **zry98** — maintainer, [`zry98/movistar-home-hacks`](https://github.com/zry98/movistar-home-hacks) (GPL-3.0).
* **alfredopironti**, **alxayu97** — code contributors.
* Community credits named in that repo's README: **Cansi**, **Carlos**,
  **Howard**, **Iscle** ([@iscle](https://github.com/iscle)), **José**, **Pablo**,
  **Nadia Santalla** ([@nadiamoe](https://github.com/nadiamoe)), **P4blo24**,
  **josemoraocana**, **Alfredo** ([@alfredopironti](https://github.com/alfredopironti)),
  **Chocomerde**, **Lucas Sánchez**, **Tony**, **Javier**, **Ángel Luis**,
  **[@alxayu97](https://github.com/alxayu97)**.
* Telegram community: [@movistar_home_hacking](https://t.me/movistar_home_hacking).

Device facts cross-checked there: Snapdragon 625 (8C8T Cortex-A53) @1.8 GHz,
3 GB RAM, 32 GB eMMC, **armv7l (32-bit) userspace on an arm64-capable SoC**,
8" 1280x800 Goodix I2C touch, QCA9379 Wi-Fi/BT, OV2735 camera.

## Prior 3.18 KGSL hardening

* **Deepak Kumar** — vendor commit `0a4ef64e3f`, *"Return mementry only if
  `pending_free` is not set"* (msm-3.18, 2017-05-08), upstream-identical text at
  `0e42ef24…`. We show it only guards `kgsl_sharedmem_find()`,
  not the SVM/`gpuaddr` sharing.

## CVE-2019-2215 (binder) — the read oracle

* **Jann Horn**, **Google Project Zero** — *"Bad Binder"* (CVE-2019-2215).
* Public PoCs adapted here:
  * [`wired0ut/CVE-2019-2215`](https://github.com/wired0ut/CVE-2019-2215)
  * [`LIznzn/CVE-2019-2215`](https://github.com/LIznzn/CVE-2019-2215)
  * [`kangtastic/cve-2019-2215`](https://github.com/kangtastic/cve-2019-2215)
* **Maddie Stone**, *"Bad Binder: Android In-The-Wild Exploit"* (Project Zero /
  Android Security) — public analysis of the in-the-wild chain.

## Tooling

* **REA** (reverse-engineering agent) — used to reduce the 26 MB kernel image
  and lift `kgsl_*` procedures to pseudocode.
* **Ghidra** — disassembly / cross-checking of the shipped kernel.
* **zig** (`zig cc`) — arm32-musl static cross-compilation of the harnesses.
* **musl** / **Termux** — the `untrusted_app` runtime.

## Advisors

Several unnamed reviewers/consultants contributed critiques through the
`consult-*.md` documents that shaped the plan (notably the correction that freed
KGSL pages go to the **KGSL FIFO page pool**, not buddy, and the "probe artifact"
warning about async command-buffer reuse).

## Assets

* Kernel driver source excerpts referenced under `reports/` are property of
  **Qualcomm / The Linux Foundation** and are cited, not redistributed.
* `reference/kgsl-uapi.h` is the upstream UAPI header (`include/uapi/linux/msm_kgsl.h`,
  GPL-2.0), included for reference only.
