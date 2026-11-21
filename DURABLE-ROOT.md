# Durable root — the box rebuilds its own `uid 0` ~2 min after every power‑on

Companion to **[GUIDE.md](GUIDE.md)**, which ends with a working forged‑PTE kernel
R/W and a *parked* root worker. Everything after that point — surviving a reboot,
and surviving the next one with **zero hands** — is this file.

> **Verified on hardware.** A full power cut (smart plug, ~20 s off, no human
> steps): root back **~2 min** after power‑on, BootKeeper re‑installed, `:8022`
> sshd up — reproduced across repeated unattended power cycles.

## 1. The three problems after "we have root"

| problem | what it looked like | what fixed it |
|---|---|---|
| **the win killed the box** | wins died ~1 min after `apk staged` | payload G10/G11 — remove the deadly stores (§2) |
| **root died with the worker** | the worker ended at the first reboot | BootKeeper + the agent chain rebuild root every boot |
| **every boot needed hands** | a human opened Termux and re‑ran the fire | MH‑Agent fires the payload from the app itself |

## 2. The wall: the seccomp clear was the kill switch

The endgame cleared seccomp so the worker could `exec`; that clear wrote
`mode@+0x5bc` and `filter@+0x5c0` on the `task_struct`. Kernel disassembly
(`loot/kernel.elf`, **not** stripped) confirmed both offsets were **right** — yet
roll after roll the box died **at the store**: G8/G9 wins showed
`settle1 begin → settle1 done → silence` (5 samples in the same zone). The write
vector was the killer, not the offset.

- **G10** (17:07): the two stores **and their settles were removed**; read‑only
  probes `sc.status` / `sc.read` added. Roll #34 (17:12) crossed the entire
  seccomp zone for the first time — filter ACTIVE (`mode=2`, valid `filter`
  pointer) — and the box stayed **alive**.
- **G11** (17:17): the post‑disarm `chown`+`chmod` pair deleted — `chmod` is a
  **SIGSYS‑blocked syscall** on this box and that landmine had never been reached
  before (0/N runs ever got that far); the six foreign‑slot stores moved to a
  guarded write (faults counted and posted).
- **Roll #35 (17:20) = win #14** — first time the *whole* endgame ran:
  `disarmed faults=0` → `sshd2 spawned` → `worker forked pid=… ALIVE` → BK
  installed (`__BK_DONE=0`).

## 3. Why `pm install` failed once root existed (and the one‑line fix)

The worker runs as `context=u:r:kernel:s0`. From that context `service list`
returns **"Found 0 services"** — servicemanager filters it — so `pm`/`am` answer
*"Could not access the Package Manager. Is the system running?"*. Fix, proven
live:

```sh
echo u:r:shell:s0 > /proc/self/attr/current   # permissive allows the transition
pm install -r /data/local/tmp/BootKeeper.apk  # Success
```

That line lives in the stroke, and in every helper that calls `pm`/`cmd`/`am`.

## 4. The boot chain (what happens after power‑on)

```
power on
 ├─ BootKeeper (BOOT_COMPLETED receiver)                ~t+15 s
 │    └─ launches the Termux activity
 │         └─ ~/.bashrc -> ~/start.sh
 │              ├─ sshd :8022 (+15 s keeper)
 │              ├─ job poller + MHBOT heartbeat
 │              └─ clock fixer (see APPLIANCE.md §5)    ~t+4.5 min
 └─ MH-Agent (service on :8080)
      └─ fires the payload itself                       uptime ~41 s
           └─ KGSL race wins -> worker (uid 0)          uptime ~128 s
                └─ agent drives it with bk-stroke.sh    seconds later
                     └─ pm install BootKeeper (staged)  __BK_DONE=0
```

Timings are from the 17:42 power‑cut test and a later unattended reboot.

## 5. Components

### BootKeeper — `com.mh.bootkeeper` (12,703 B)
One job: `BOOT_COMPLETED → startActivity(com.termux/.TermuxActivity)`. It is an
**app** because a boot receiver is the one thing a non‑root helper cannot fake.
On 8.1 a sideloaded app does not receive `BOOT_COMPLETED` until launched once
(`stopped=true notLaunched=true`); one `am start` fixes it, and every win
re‑installs it (`pm install -r`, base.apk salt dir changes).

### MH‑Agent v4 — `com.mh.agent` (`:8080`)
- fires the payload from its **own mailbox** at boot (no Termux, no human);
- worker round output is chowned to the app; the drive gate greps
  `payload staged|PAYLOAD:` (never a stale file) and re‑asserts the stroke if a
  foreign writer clobbers `rootcmd`;
- policy: **one free auto‑retry**, then `backoff engaged` until
  `GET :8080/run` (force one fire) or `:8080/stop` (disarm);
- **`POST /cmd` = root shell**: writes the body to the worker mailbox, returns
  the output. This is the project's daily door.

### The stroke — BK install, served live
`upload_server.py` special‑cases `GET /bk-stroke.sh`: it extracts the `$BKS`
block from the **current `job.sh`** on every request, so the served stroke can
never drift from the job's copy (currently **811 B**). It switches context to
`u:r:shell:s0`, prefers the **staged** APK (`__BK_USE_STAGED__`), runs
`pm install -r`, and prints the `__BK_*` markers.

### `job.sh` — verdict‑delivery stub (18,093 B)
The fire body is decommissioned: BootKeeper revives the Termux chain every boot,
and the old body's `rm rsh.alive/rootcmd` used to collide with the agent drive.
The stub still delivers the **previous** run's verdicts (`kgsl-out.txt`,
`stage.txt`, `rootout.txt`, …) before they are truncated — so every boot answers
"what did the last roll do" within seconds of the heartbeat.

### The Termux chain
`~/.bashrc` → `~/start.sh`: sshd (+15 s keeper), job poller, MHBOT heartbeat,
then the clock fixer. The pid‑file guards verify `/proc/$pid/cmdline`, not just
`kill -0` — a recycled PID once made a dead boot look alive and silently skipped
a whole draw.

## 6. Doors

The control channel (`:8080`) binds to **`127.0.0.1` only** — it runs a shell as
uid 0 with no authentication, so it must never be exposed on the LAN. Reach it
through the ssh tunnel: `ssh -p 8022 -N -L 8080:127.0.0.1:8080 <box>`, then use
`127.0.0.1:8080` from the host.

| door | how | notes |
|---|---|---|
| root shell | `POST http://127.0.0.1:8080/cmd` (body = shell) | uid 0, `u:r:kernel:s0`; loopback-only, via the tunnel above; keep the script < ~20 s; prefix `echo u:r:shell:s0 > /proc/self/attr/current;` for `pm`/`cmd`/`am` |
| ssh | `ssh -p 8022 <box>` (u0_a42, key‑auth) | revived every boot by BootKeeper |
| force a fire | `GET :8080/run` | ignores backoff/stop flag, one run |
| disarm | `GET :8080/stop` | will not fire on its own until `/run` |

## 7. Recovery ladder

1. **Silence after a fire, ports still answering → do not cut.** Probe a unique
   token through `/cmd` (`printf 'id; echo TOK_$$\n' > ~/rootcmd`): a live worker
   answers, a stale file cannot. A win can be completely silent.
2. **No root this boot** (both rolls lost) → `GET :8080/run`, wait ~2 min, repeat.
3. **Dead box** → power cycle (smart plug). Root returns by itself.

Never `pm install -r` over the running agent (it kills the driver mid‑drive;
agent updates go through `/cmd` by hand). Never edit `/system`.

## 8. Ledger

n = 35 rolls: **14 wins, 6 clean parks, 15 fast dies** (pre‑race). Fast dies are
not artifact‑linked. Win rate per fire ≈ 40 %, and the agent's free retry gives
roughly two fires per boot.

## 9. Files

| path | what |
|---|---|
| [chain/bootkeeper/](chain/bootkeeper/) | BootKeeper app source + build |
| [chain/agent/](chain/agent/) | MH‑Agent v4 source + build |
| [chain/device/](chain/device/) | the box boot scripts (`start.sh`, `bashrc`) |
| [exploit/](exploit/) | the KGSL payload (`kgsl-forge.c`) + build |
| [GUIDE.md](GUIDE.md) | the exploit end‑to‑end |
