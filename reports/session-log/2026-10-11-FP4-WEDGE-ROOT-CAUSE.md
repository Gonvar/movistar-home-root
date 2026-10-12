# FP4/JOB-84 wedge — root cause & the corrected write primitive

**Date:** 2026-10-11 ~19:05 (session 4)
**Supersedes:** the "pending run never executed" claim in `2026-10-11-HANDOFF.md` §3.

## 1. What actually happened after the handoff was written

The handoff (~18:25) said the fp4 run was staged but never executed. The upload
server log shows otherwise — the poller **did** run JOB-84:

```
18:24:03  GET /job.sh      (2109 bytes = JOB-84 version)  from .132
18:24:04  GET /poc-fp4.gz  (31055 bytes, md5 ok)         from .132
     ...   NO result upload, NO further polls, ever.
```

Expected upload time was ~18:26 (run + POST). None came, and the poller's
15-second job.sh GETs stopped completely. The box **answers tcp/7547 right now**,
so it is alive.

## 2. The crash was not a crash — it is a deterministic CPU wedge

Disassembly of this kernel (`loot/kernel.elf`), all addresses verified:

**`_raw_spin_lock` (c0c98c30) is a TICKET lock:**

```
preempt_count_add(1)                    <- preemption OFF
ldrex r2,[r4] / add r3,#65536 / strex   <- tail += 0x10000
... spin: ldrh owner ; cmp until owner == my_ticket
```

Lock word = `(tail<<16 | owner)`; **unlocked iff the 16-bit halves are equal**
(matches the live-observed `0x00860086 -> 0x00870087` cycle).

The DEL's `remove_wait_queue` does `spin_lock(&freed_thread->wait.lock)`, and
after the victim's import reclaims the freed slot, that lock word is at
`array+0x50` = **`iov[10].base`**.

- **Leak rounds set `iov[10].base = g_junk_pre = X*0x10001` — equal halves, a
  valid unlocked ticket. The spin passes instantly.** The fp4 source comment
  even documents this ("must have equal halves").
- **fp4 dropped `map_ticket_junk()` entirely and set `iov[10].base = BUF_A`**
  (~0x0F3E0000: owner=0x0000, tail=0x0F3E). The spin waits for the owner half
  to be incremented 0x0F3E times — **it spins forever, with preemption off.**

Consequences, all consistent with observation:

- CPU0 is wedged permanently (8-core SoC; the other 7 keep the box alive —
  7547 answers).
- The poc task is **unkillable** (never returns to userspace), so
  `timeout -k 10 120` can never collect it, job.sh never finishes, the
  poller's bash is blocked inside it forever → no upload, no more polls.
- No kernel data was corrupted by fp4's probe write (see §3 — it never ran).
- **Irony worth banking: the wedge is proof the fp4 reclaim DID land.**
  NUM_IOVECS=64 put the victim's array in the freed binder_thread's slot
  exactly as designed; the round then died on its own lock-word bug.

## 3. Two copy-path findings that reshape the whole write design

### 3a. Socket recvmsg path: kernel destinations are structurally refused

`memcpy_toiovecend` (c039aa1c), disassembled in full:

```
aa40: ldr r4,[r7,#-4]      ; per-segment iov_len reload
aa50: ldr r9,[r7,#-8]      ; per-segment iov_base reload  (the "reload" M4 found)
aa60: ldr r3,[r8,#0x8]     ; thread_info->addr_limit
aa68: adds r2,r9,r4 / sbcslo / movlo r3,#0     ; inlined access_ok(dst+len < limit)
aa7c: bne -> cmp r0 ; bne aae0 -> mvn r0,#13    ; dst >= 0xBF000000 => return -EFAULT
aa8c: bl __check_object_size   ; called on the KERNEL SOURCE, never the dst
aab0: bl arm_copy_to_user       ; plain copy (DACR D1=client dance)
```

**Any iovec destination in kernel space → clean `-EFAULT`. No panic, no write,
no crash.** So fp2/fp3/fp4's `recvmsg`-victim self-overwrite design could never
work on this kernel, regardless of reclaim. (And it means the 18:24 wedge was
the *only* dangerous thing fp4 did.)

### 3b. Pipe readv path: kernel destinations are ALLOWED

`copy_page_to_iter` (c02011c8):

```
1238: ldr r8,[r6]          ; per-segment iov_base reload (fresh each entry)
1258-12dc: strbt probes on dst, first and last byte, under DACR D1=client
           -> kernel direct-map pages are DOMAIN 0 (manager): probe PASSES
              for kernel addresses; unmapped dst => fixup => short count (safe)
1300: bl __check_object_size ; on the SOURCE (the pipe page), never the dst
1330: bl arm_copy_to_user    ; plain copy — kernel dst lands if mapped
```

There is **no addr_limit check on the destination** anywhere on this path, and
the DACR probe only rejects unmapped/user-RO destinations. **A redirected
iovec base pointing at mapped kernel memory is written for real.** This is the
write channel. (The leak rounds' `rx()` already exercises this exact path with
user destinations; `__check_object_size` on pipe-page sources is proven safe
in every run.)

This resolves the old consult-sol3 confusion: the "strbt probe" is a
mapped/writable probe, not a kernel-address gate; and the "no gate" retraction
was right for the pipe path but the socket path was never re-checked — it has
a hard gate.

## 4. fp5 — the corrected write round (staged, NOT yet run)

`binder-exploit/poc-fp5.c` → `poc-fp5.gz` (md5 `5d5c3a1b84a891d72e0cc67945bc7f99`,
30327 bytes, armv7 static musl). Changes vs fp4:

1. **`map_ticket_junk()` restored; `iov[10].base = g_junk_pre`** (equal halves
   → DEL's spin_lock passes instantly). Pre-drain byte lands harmlessly in the
   junk region. The wedge is structurally impossible.
2. **Victim = `readv` on a pipe** (fork, exactly the leak round's skeleton) —
   the §3b path where kernel destinations work.
3. **Proof target = `linux_banner` (0xC0D0004A) + 0x20**, payload `"PWNPWNP1"`.
   `_etext = __start_rodata = 0xC0D00000` → the banner is .rodata **string
   data past text**; the kernel never parses it. Observable via `/proc/version`.
   - If the redirect lands: banner changes → **arbitrary kernel write proven**,
     zero functional impact (cosmetic string; restored by reboot).
   - If the reclaim misses: all bytes go to the user instrumentation buffers,
     full count, DEL hit a sprayed binder_proc's empty wait head (lock=0 is a
     valid unlocked ticket; twin writes restore the empty-queue self-pair —
     benign, same as every leak-round miss).
   - No vmalloc addresses (0xDEADC0DE-style gambles removed), no `init_task`,
     no live kernel objects targeted.
4. Instrumented verdict table, `/proc/version` printed before/after in-poc.

Residual risk: same as ~20 clean leak rounds (DEL on a reclaim miss hitting a
random system kmalloc-512 object). Accept per session rules; power-cycle is
the accepted recovery.

## 5. Recovery procedure (physical)

The wedged fp4 task cannot be killed (`timeout`/`SIGKILL` undeliverable in a
preempt-off spin). Options:

1. **Without power-cycle (forensics first):** in Termux run
   `pkill -9 -f poller.sh; pkill -9 -f 'poc-'; setsid nohup bash ~/poller.sh > ~/poller.log 2>&1 &`
   — the new poller fetches the staged JOB-85 health check, which reports
   uptime, loadavg, and whether a `poc-fp4` task is still alive in D/R state
   (confirms the wedge theory live) plus the `/proc/version` baseline.
2. **Then power-cycle the device** to reclaim CPU0 (red-lines-acceptable).
3. Restart the poller again in Termux (same command).
4. Only after a healthy JOB-85 result + explicit go-ahead: flip `job.sh` to
   JOB-86 (fp5 banner write). One run, then wait for the result.

## 6. CVE status after this session

- **CVE-2019-2215 (binder)**: read primitive DONE (leak round, ~20 clean
  runs). Write primitive: design corrected in fp5; wedge bug found and
  structurally removed; socket-path dead end identified (fp2/3/4 results
  fully explained); pipe-path write channel confirmed by disassembly.
- **CVE-2021-1905 (kgsl pid-number reuse UAF)**: **confirmed present in this
  kernel** (KGSL-AUDIT round 5; fixes `93fde26e`/`22ea8192` absent) — prime
  candidate for the GPU-write endgame that bypasses usercopy entirely; pairs
  with the 2215 physmap read for target locate+verify.
- Dead: 2014-4014, 2017-14491 (under red lines), 2021-28663, 2022-25720
  (contained), 2022-22077. JDWP/adbd paths remain closed (earlier sessions).
