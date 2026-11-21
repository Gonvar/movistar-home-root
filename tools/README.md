# tools/ — the hands‑free iteration loop

The device is a locked‑down speaker with **no usable `adb`** (adbd crash‑loops and
`set_prop` is denied to `untrusted_app`), so development was driven over **HTTP +
Termux** from a host on the same LAN.

```
host                                      device (Termux, uid 10042)
upload_server.py :8010   ──GET /wait──▶    ~/poller.sh   (long‑poll loop)
  serves job.sh, *.gz                        └─ runs ~/job.sh when it changes
  stores POSTed output    ◀──POST /──        ~/job.sh      (one run, streamed)
```

> A **`sshd`** (Termux `pkg install openssh`, port **8022**) is a better channel once
> it's up — `ssh -p 8022 <user>@<device>` gives a real shell and `scp`. It does not
> survive a reboot without the Termux:Boot addon, so keep a small `~/start.sh` that
> relaunches `sshd` + the poller.

## `upload_server.py` (host, `:8010`)

Threaded HTTP server that

* serves whitelisted files (`job.sh`, `kgsl-forge.gz`, `poller.sh`, …),
* stores every `POST` body as `uploads/upload-<ts>.bin`,
* provides **`GET /wait`** — a long poll that returns the **instant `job.sh`
  changes** (or ~20 s), so job delivery is ~0.1 s instead of a 15 s poll.

## `poller.sh` (device, `~/poller.sh`)

Loops on `GET /wait`; when `job.sh` changes it runs it (hard timeout), POSTs the
output, and **preempts** a still‑running job. It **auto‑runs once at startup**, so a
fresh boot runs the job by itself.

## `job.sh` (device, `~/job.sh`)

The unit of work: **self‑heal** (kill leftover exploit processes), **guard** (refuse to
forge unless the device is fresh — `uptime` sane and zero live `kgsl-forge`), **single
attempt**, and stream diagnostics every 2 s. It also drops a `~/r "<cmd>"` helper that
drives the detached root worker.

> `job.sh` / `poller.sh` embed the host's LAN address — adjust for your own network.
