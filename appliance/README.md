# appliance/ — the software that runs *on* the box

Sources for everything that lives on the rooted Movistar Home after the exploit.
Context: [../DURABLE-ROOT.md](../DURABLE-ROOT.md) (how root comes back by
itself) and [../APPLIANCE.md](../APPLIANCE.md) (what the box was turned into).

| path | what |
|---|---|
| `launcher-app/` | **MH Launcher** (`com.mh.launcher`) — the from‑scratch home screen. Framework‑only Java, no Gradle: `cd launcher-app && ./build.sh` (needs an Android SDK; override with `ANDROID_SDK=…`). The signing keystore is generated on first build and is **not** committed — keep yours outside the repo so reinstalls stay signature‑compatible. |
| `deploy.sh` | `./deploy.sh` — build + push + install + set HOME, one command |
| `tools/` | operator tools (see the table in [../APPLIANCE.md](../APPLIANCE.md#7-tools)); `tools/box/mh.sh` is the on‑box helper — push it to `/data/local/tmp/mh/mh.sh` and run it through the root door |
| `device-tools/` | small static ARM32 helpers written during the strip |

**Addresses here are redacted:** `192.168.1.100` is the box, `192.168.1.101` is
the host that serves the exploit. Set your own before use.
