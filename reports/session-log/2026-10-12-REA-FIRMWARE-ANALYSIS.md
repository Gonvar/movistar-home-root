# REA firmware analysis — setup, off-kernel audit, kernel decompilation

Date: 2026-10-12. Author: agent session. Target: `Desktop/movistar-home-analysis/stock-3.7.0`
(= live device, verified byte-for-byte on version).

## 0. Tooling now working

- `rea` 6.4.0 had **no analysis engine** (`ghidra` not_configured, `hopper` missing, `ida`
  unregistered; JDK 17 too old). Installed:
  - `brew install ghidra` → Ghidra **12.1.4** at `/opt/homebrew/opt/ghidra/libexec`
    (pulled `openjdk@21`, 21.0.12.1).
  - Env: `GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec`,
    `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (see `rea-env.sh`).
  - `rea doctor` now green for ghidra (version/installation/headless/native_decompiler/java).
- `rea decode-android-resources` works (apktool 3.0.3) for APKs.
- **Kernel work-around:** `loot/kernel.elf` (26 MB) exceeds REA/Ghidra's fixed startup budget
  (`REA_GHIDRA_STARTUP_TIMEOUT_MS` default 330 s; failure = `provider_timeout` on
  `list_documents`). REA re-imports per call (no project persistence), so a full-kernel import
  is unusable. Built **reduced ET_EXEC windows** with correct VMA + `STT_FUNC` symtab:
  - `rea-work/kern/afunix.exec.elf` — VMA `0xc0ab0000..0xc0ba0000` (af_unix / scm / skb),
    4125 procedures, entry `unix_gc`. Evidence `ev_651b1d017885419944e9c18e249bf24cdeef08f5de48535b3e978c886a28664e`.
  - `rea-work/kern/kgsl.exec.elf` — VMA `0xc050e000..0xc0528000` (KGSL), entry
    `kgsl_mmu_getpagetable` (not yet decompiled).
  - Builder + pseudocode under `rea-work/kern/`. Symbols from `loot/kernel-symbols.txt`.

## 1. Off-kernel audit (bounded negatives)

### 1a. `netd` (uid 0) resolver — hardened upstream bionic, no bug found
`extracted-system/bin/netd` imports `android_getaddrinfofornetcontext` (LIBC_PRIVATE) →
`extracted-system/lib/libc.so` `__res_nsend` / `dn_expand` / `__ns_name_unpack` /
`__res_queriesmatch`. The device already resolves through our Mac, so this is a real root
parser reachable over WiFi. Decompiled the core parsing (all Evidence retained):
- `__ns_name_unpack2` `0x33b34`: output bound `param_4+param_5 <= pbVar7+__n+1`, pointer
  bound `param_2-param_1 <= uVar5`, loop budget `iVar6 < param_2-param_1`. **Safe.**
- `__ns_name_ntop` `0x33490`: per-segment output bounds (`pbVar13 <= pbVar3+iVar4`). **Safe.**
- `dn_expand` `0x3c448` = `__ns_name_uncompress` wrapper + trailing-dot strip.
- `__res_queriesmatch` `0x3eea8`: 1026-byte stack buf, `dn_expand(...,0x402)` bounded.
  **Safe.**
Verdict: standard AOSP bionic (patch 2021-10-05). No reachable memory bug identified.
Evidence: libc overview `ev_9d9e8f1b0a76f330688f29b3f27d8ba141e51bece6580cf59f2f67a387e014f4`,
netd overview `ev_f57d2ee3977912a2df20c981d7d4086e0e666b3ecc5b19c4dae37f110efec6b7`.

### 1b. Other network services
- `tftp_server` (init `class core`, user root, `init.svc.tftp_server=running`) is **not**
  network-reachable: imports `AF_MSM_IPC`/`MSM_IPC_ADDR_ID`, Qualcomm QMI/RFS transport, and
  drops UID/caps to `rfs`. Dead end.
- DHCP client is **Java (uid 1000)**, not `dhcpcd`: `do_stop: Service dhcpcd not found`; the
  `dhcpcd_*` services are `disabled`+`oneshot`. Option-60 parse (`[Askey][DhcpResults]HGU: ...`)
  surfaces via `WifiService`.
- No init `socket` is AF_INET; only all-interface TCP listener is **7547 (AskeyTR69, uid 1000)**.
- IMS/SIP parsers (`lib-imsSDP.so`, `lib-imsxml.so`, `lib-rtpcore.so`) are QMI-fed by the
  modem, not WiFi-reachable. `mdnsd` (mDNSResponder, `mdnsr` uid) is `disabled` and not running.

## 2. Kernel af_unix GC (CVE-2021-0920) — REA decompilation Evidence

Vulnerable structure confirmed in the vendor 3.18.71 binary (fix `cbcf01128d0a` absent).

### `unix_gc` (`0xc0b9caec`) — Evidence `ev_5b9945fbb5d48f5bbc63c940a907d066b621d764c94cebeb340547250eb00dee`
Synchronous 3.18 GC, matches upstream exactly:
1. `spin_lock(&unix_gc_lock)` (`func_0xc0c98c30(0xc16dd9d8)`).
2. candidate selection over `gc_inflight_list`, `list_move_tail(&u->link, &gc_candidates)`,
   set CANDIDATE/MAYBE_CYCLE (`|3` on `gc_flags`).
3. `scan_children(..., dec_inflight, 0)`.
4. `scan_children(..., inc_inflight_move_tail, 0)`.
5. `scan_children(..., inc_inflight, &hitlist)`.
6. `spin_unlock`; `__skb_queue_purge(&hitlist)` i.e. the while-loop calling **`kfree_skb()`**;
   `spin_lock`; `BUG_ON(!list_empty(&gc_candidates))`; clear `gc_in_progress`;
   `wake_up(&unix_gc_wait)`.

**The GC frees the hitlist skbs while holding no lock w.r.t. a concurrent reader** — the window.

### `unix_dgram_recvmsg` (`0xc0b9c088`) — Evidence `ev_999e304f4afe938b2d91882f4625215e2bc97a8408d76f03985540f9d57a8133`
The vulnerable MSG_PEEK vs non-PEEK split (decompiled):
```c
UNIXCB(skb).fp  == *(int*)(skb + 0x24)      // scm_fp_list* stored in the skb
if ((flags & 2) == 0) {                      // NOT MSG_PEEK (MSG_PEEK == 2)
    if (*(int*)(skb + 0x24) != 0) unix_detach_fds(scm, skb);
    /* advance peek offset */
} else {                                     // MSG_PEEK
    if (-1 < *(int*)(sk + 0x1b4)) *(uint*)(sk + 0x1b4) += n;
    if (*(int*)(skb + 0x24) != 0) {
        scm->fp = scm_fp_dup(*(int*)(skb + 0x24));   // <-- reads the freed fp list
    }
}
```
This is precisely the bug: a non-PEEK `recvmsg` clears `UNIXCB(skb).fp`
(`unix_detach_fds` sets `skb+0x24 = 0`) while a concurrent `MSG_PEEK` is between reading the
skb and calling `scm_fp_dup` → `scm_fp_dup` reads reclaimed memory. The fix makes MSG_PEEK take
`unix_gc_lock`. **`unix_peek_fds` symbol absent — pre-fix code confirmed.**

### `scm_fp_dup` (`0xc0acb9f4`) — Evidence `ev_e2747a3a9c8ff9682f3070fdceb27b48f409784afecfc75a14cebf3520bd1bd2`
```c
new = kmemdup(fpl, fpl->count*4 + 4, GFP_KERNEL);   // 0xc01f5b50 == kmemdup, 0xd0 == GFP_KERNEL
for (i = 0; i < fpl->count; i++) get_file(fpl->fp[i]);   // <-- get_file on attacker-chosen ptr
new->max = new->count;
```
So the controlled read is the `struct file *fp[]` array of a freed `scm_fp_list`, and the sink is
`get_file()` per entry (→ acquire refs / later use-after-free of a file). **Reclaim target = the
freed `scm_fp_list` (kmalloc, size `count*4 + 4`) and/or the freed `sk_buff`
(`skbuff_head_cache`, `UNIXCB(skb).fp` at offset 0x24).**

### `unix_destruct_scm` (`0xc0b99310`) — Evidence `ev_a7d23b5489cabd61d5ae00aabcc15c0197e65e445428daf3aebc1b9c24bf7fe7`
`kfree_skb(skb)` → `unix_destruct_scm`: `unix_detach_fds(scm, skb)` (→ `unix_notinflight` per fd)
then `__scm_destroy` (fput each file) then `sock_wfree`. i.e. the free order for a hitlist skb is:
detach fds → free `scm_fp_list` → release `sk_buff`.

### `unix_detach_fds` (`0xc0b991e8`) — Evidence `ev_9e78172c635c7452886042e4f090992a52a4e08bd61c58149932258776e68d4a`
`skb+0x24 -> scm->fp; skb+0x24 = 0; for each fp: unix_notinflight()`.

## 3. What this changes for the root plan

- The off-kernel "free uid-1000 via native parser" hope is **closed twice** (bionic DNS hardened;
  no other WiFi root parser). The kernel path remains correct.
- The af_unix endgame targets are now pinned to real addresses/fields in the *device* kernel
  (not upstream): `unix_gc` hitlist purge → `kfree_skb`, `UNIXCB(skb).fp @ skb+0x24`,
  `scm_fp_dup` → `kmemdup(count*4+4)` + `get_file`.
- Next concrete probe: derive the `sk_buff` / `scm_fp_list` layout offsets from `afunix.exec.elf`
  and build the reclaim (`sendmsg` skb spray vs kmalloc-8/16/32 spray) so the race leaks
  instead of panicking; KGSL window (`kgsl.exec.elf`) is staged as the alternate.
