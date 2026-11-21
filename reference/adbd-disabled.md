# adbd on this device: why there is no `adb` over USB or Wi‑Fi

**Short version.** `/system/bin/adbd` on the ASKEY RG3205W ("Movistar Home") is a genuine,
statically linked AOSP `adbd` — Telefónica‑customised — that **exits with status 0 a few
milliseconds after `init` starts it**, before it ever registers a transport or enters its
event loop. `init` respawns it every ~5 s, so `init.svc.adbd` flaps and **nothing ever
listens: not USB, not :5555, not :5037**. No property, no key and no `adb_secure` setting
changes this, because the daemon is gone before it reads them.

Everything below came out of one root run's read‑only recon (`/dev/kmsg`,
`/system/bin/adbd`, `/proc`, the vendor `*.rc` files) — see §9 of [GUIDE.md](../GUIDE.md) for
how the recon was collected.

---

## 1. What `init` sees

```
init: processing action (sys.usb.config=diag,adb && sys.usb.configfs=0) from (/vendor/etc/init/hw/init.qcom.usb.rc:175)
init: starting service 'adbd'...
init: Created socket '/dev/socket/adbd', mode 660, user 1000, group 1000
init: Service 'adbd' (pid 614) exited with status 0
init: Sending signal 9 to service 'adbd' (pid 614) process group...
init: Successfully killed process cgroup uid 0 pid 614 in 0ms
   ... ~5 s later, the same four lines with pid 1416, then 1676, 1677, ...
```

Two things to note:

* **`exited with status 0`** — not `killed by signal 6/11`. This is `WIFEXITED` with a 0
  exit code: the program *chose* to return from `main()`. It is not crashing, not being
  OOM‑killed, and not being denied by SELinux (there is **no AVC line** anywhere near it).
* The socket *is* created by `init` (`socket adbd stream 660 system system`) and passed in.
  `adbd` simply never gets as far as using it.

The service definition (from `/system/etc/init/hw/init.usb.rc`, the stock AOSP file):

```
service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
    class core
    socket adbd stream 660 system system
    disabled
    seclabel u:r:adbd:s0
```

Started by the *vendor* trigger `on property:sys.usb.config=diag,adb && sys.usb.configfs=0`
(`/vendor/etc/init/hw/init.qcom.usb.rc:175`), i.e. the `diag,adb` USB composition.

## 2. The binary is real, and it is still on the device

```
$ file adbd
ELF 32-bit LSB executable, ARM, EABI5, statically linked,
BuildID[md5/uuid]=e36e4b3d032eeb9adbd828cff3bd2d61, not stripped
```

* **Statically linked** — no `/system/lib` dependencies at all.
* **Not stripped** — full C++ symbols (`_Z9adbd_maini`, `_Z12fdevent_loopv`, …), so the
  whole question is answerable offline with `nm`/`objdump`.
* Contains the real AOSP code: `adbd_main(): pre init_jdwp()`, `usb:`, `tcp:%d`,
  `service.adb.tcp.port`, `persist.adb.tcp.port`, `ro.adb.secure`, `adbd cannot run as root
  in production builds`, `sys.powerctl`, `init.svc.mdnsd`, and Telefónica‑specific strings
  (`ro.target.customer`, `ADB_EXTERNAL_STORAGE`). It is an operator build of `adbd`, not a stub.

## 3. Where it dies

`main()` parses options and then calls `adbd_main(0x13ad)` — port **5037** — and returns
whatever it returns. So a `status 0` means *`adbd_main` returned 0*.

Two facts from the disassembly pin it down:

1. **`adbd_main` has exactly one exit** — a single `pop.w {r4-r11, pc}` at `0xbbc6` — and
   **no `exit()`/`abort()`/`__android_log_assert()` call anywhere**. The only fall‑through
   into that epilogue is the instruction immediately after a `bl fdevent_loop()`.
2. **`fdevent_loop` is the real loop** (0xa1c bytes: signal masking, `gettid`, `fcntl`, the
   `epoll`/`select` body) — not a stub.

And the very first thing `adbd_main` does is a property gate:

```
GetProperty("ro.build.type", "") == "user"  →  jump to 0xba16
                                 else       →  fall through (a ~1.1 KB skipped block)
```

On this box `ro.build.type=user`, `ro.secure=1`, `ro.adb.secure=1`, `ro.debuggable=0`
(`ro.build.tags=test-keys`). So the *taken* path is the one that ends by returning from
`adbd_main`, having called `local_init()`, `setup_mdns()`, `init_jdwp()` and — as the last
thing — the global‑bool checks that gate `fdevent_loop()`, but **never**
`init_transport_registration()`, `usb_init()` or `fdevent_loop()` itself.

Practical reading: on this operator build, `adbd` is deliberately neutered by a
build‑type/operator check in its startup prologue. It exits cleanly before advertising any
transport, which is exactly the behaviour you want if you are the ISP and you do not want
field `adb`.

> To reproduce the analysis, with the `adbd` binary pulled by any means:
>
> ```sh
> nm -S adbd | grep -E "_Z9adbd_maini|_Z12fdevent_loopv"      # 0xb5a8 (size 0x9d0), 0x18c34
> objdump -d --start-address=0xb5a8 --stop-address=0xbf78 adbd \
>   | grep -nE "pop\.w|bx\s+lr"                                # one exit, at 0xbbc6
> objdump -d --start-address=0xb5a8 --stop-address=0xb6c0 adbd    # the ro.build.type gate
> ```
>
> Strings live in `.rodata`; the two operands of the gate are `ro.build.type` and `user`
> (`0xcc540`, `0xcd030` in this build).

## 4. What does **not** fix it

| Attempt | Result |
|---|---|
| `setprop service.adb.tcp.port 5555` from the app | `PROP_ERROR_PERMISSION_DENIED (0x18)` — and it would not matter, `adbd` is already gone |
| same, from a property socket created *after* `cred = init_cred` | still `0x18`: property checks use the **socket's SELinux SID**, which stays `untrusted_app` — `uid 0` does not relabel you |
| `ctl.start adbd` / `ctl.restart adbd` via the property socket | **works** (returns `0`), but just respawns a daemon that exits again |
| `persist.adb.tcp.port` written as root to `/data/property/` | survives reboot and is restored as `service.adb.tcp.port` — still useless, the daemon exits first |
| writing a new `/system/bin/adbd` | `/system` is `dm-verity` protected (`ro.boot.veritymode=enforcing`, `partition.system.verified`) |
| Developer options "adb over network" | audited on this build: **no such preference exists** in Settings |

Even `ro.adb.secure=1` and the authorised key we drop into `/data/misc/adb/adb_keys` are
irrelevant — auth happens long after the point where this `adbd` gives up.

## 5. If you really want `adb` anyway

Everything here needs **root** (§7), but it is a genuine route because the binary is static:

1. **Run your own copy.** Copy `/system/bin/adbd` to `/data/local/tmp/`, patch the startup
   gate (or drop in an unmodified AOSP `adbd` for armv7 from any Android 8.x image of the same
   era — it is a static binary with no library dependencies), and start it as root. `/data` is
   executable and SELinux is permissive once the exploit has run, so it runs where it stands.
   In 8.1's `adbd` the TCP port still comes from `service.adb.tcp.port`, which root can write
   into the property area — and `/data/misc/adb/adb_keys` is already seeded with a host key,
   so no on‑device authorisation prompt.
2. **Check the uid dependence first** (cheap): run the stock binary by hand as the app uid and
   as uid 2000 and compare the exit. The gate sits in a build‑type/operator prologue, so it is
   worth confirming whether it keys off the *caller* at all before patching anything.
3. **Or skip `adb`.** For day‑to‑day work on this device the root worker channel (§12) plus
   `sshd` in Termux (port 8022, app uid) covers shell, file transfer, `pm`, `logcat` and
   `screencap` — the only thing `adb` adds on top is installing without root, which the browser
   tap‑install does anyway.
