# Machine A — dev dashboard (Windows)

> **If you are an AI agent:** you are running on Machine A, one of three
> laptops in a live demo. Only execute commands in this file — Machine B's
> and Machine C's commands live in `demo-machine-b.md` and
> `demo-machine-c.md` and are not yours to run. Placeholders look like
> `<<THIS>>` — ask the human operator for the real value before running a
> command that contains one, unless they've already told you. Steps marked
> **(manual)** happen in a browser, not a terminal — tell the operator what
> to click rather than trying to do it yourself. Steps marked **(wait)**
> depend on another machine; do not proceed past one until the operator
> confirms it.

**What this machine does:** generates realistic multi-device log traffic —
several real device formats from different simulated source IPs — first
into Wazuh directly, then into ULPF instead, so the same traffic can be
shown two ways.

**You need:** this repo, a Rust toolchain, and one internet connection
before step 2 (none after).

---

## 1 · Find this machine's address

This machine's address is fixed for this team: **`10.60.197.72`**. Confirm
it against the actual adapter anyway:

```powershell
ipconfig
```

Look for the adapter connected to the same network as Wazuh
(`10.60.197.6`) and confirm its IPv4 matches. If it doesn't, use whatever
`ipconfig` actually reports instead of the value above — the two machines
must be reachable from each other, not just carry expected-looking
addresses.

## 2 · Build and verify (needs internet, once)

Run every line below **in the same PowerShell window, in this order**, and
read each one's output before moving to the next — do not paste the whole
block at once and assume it worked.

```powershell
git clone https://github.com/D3v4nshPat3l/ULPF.git
cd ULPF
```

```powershell
cargo build --release --locked
```

This step needs internet and can take several minutes the first time.
Confirm it actually finished with `Finished` and no `error[...]` lines
above it — a build that fails partway can still leave an *old* binary at
`.\target\release\ulpf.exe` from a previous attempt, which then runs but
behaves like an older version. If in doubt:

```powershell
Test-Path .\target\release\ulpf.exe
Get-Item .\target\release\ulpf.exe | Select-Object LastWriteTime
```

```powershell
cargo test --workspace --release --locked
.\target\release\ulpf.exe test --packs packs
```

Expect `35 packs · 75/75 fixtures passed · 100.0% field accuracy` from the
last one. Do not proceed to step 3 if any of this fails — fix the build
first; every later step assumes a working binary.

## 3 · Fetch the real log corpora (needs internet, once, ~150 MB)

Run this from inside the `ULPF` folder (the same directory `cd`'d into
above) — the destination is relative to wherever this command is run,
**not** fixed to one location:

```powershell
python tools/fetch_datasets.py
```

With no `--dir` given, this creates `realdata` **inside** the current
directory (`ULPF\realdata`, listed in `.gitignore` so it's never
committed). Confirm it actually exists and has files in it before
continuing — an empty or missing folder here is the single most common
reason the `/dev` page shows every source as "absent" later:

```powershell
dir realdata
```

Expect to see files like `iptables.log`, `snort.log`, `apache-access.log`,
etc. — not an empty directory or a "cannot find path" error.

## 4 · Phase 1 — send real traffic into Wazuh directly

Run this **from the same `ULPF` directory** as steps 2–3 — `--packs packs`
and `--datasets realdata` are both relative paths, and this command will
fail immediately if run from anywhere else. Wazuh's address is fixed for
this team — `10.60.197.6` — no placeholder to fill in here:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target 10.60.197.6:514 --no-auth
```

**`--no-auth` is required here, not optional** — without it, `/dev` sits
behind the same console-token check as every other route (confirmed
directly in `crates/ulpf-cli/src/server.rs`: `/dev` is inside the same
guarded router as `/api/*`), and a plain browser address-bar visit has no
way to attach the `Authorization` header the check requires. Opening
`/dev` without `--no-auth` returns exactly this JSON instead of the page:

```json
{"error":"this endpoint requires a console token: send `Authorization: Bearer <token>` or `X-ULPF-Token: <token>`. ..."}
```

That is not a bug to work around with the printed token — a bare page
load in a browser cannot send that header at all, token or not.
`--no-auth` is the correct fix specifically for this instance, because
this is throwaway local traffic-simulator control, not the real collector
console judges will see (Machine B keeps its token — see
`demo-machine-b.md`).

**What a correct start looks like**, printed within a second or two:

```
WARNING: --no-auth is set. Any client that can reach this port can act as the console operator.
ULPF console  ·  35 packs  ·  OCSF 1.9.0
Listening on http://127.0.0.1:8788
...
UDP receive buffer: NNNN KB
... ULPF UDP syslog receiver listening on 127.0.0.1:5515
```

No `console token:` line this time — that only prints when auth is *on*.
If nothing prints, the process exits immediately, or an `Error:` line
appears instead — **stop and read the exact error text**; it names the
actual problem (a bad path, a port already in use, a malformed argument).
Copy that exact line before trying anything else — guessing at a fix
without reading it usually wastes more time than reading it does.

A couple of things that specifically produce an early `Error:` here:

- **Port 8788 or 5515 already in use** — a previous run of this same
  command, left running in another window. Close that window, or pick a
  different `--port`/`--syslog-bind` port and use the same new one when
  opening `/dev` below.
- **`packs` or `realdata` not found** — this command was run from a
  different folder than steps 2–3. `cd` back into the `ULPF` folder first.

Once it's running and printing the block above, leave this terminal open
and running — closing it stops the simulator.

**(manual)** Open `http://localhost:8788/dev` (or `http://127.0.0.1:8788/dev`
— confirmed in `server.rs` that the console treats `localhost`, `127.0.0.1`
and `::1` as the same address for this check, so it does not matter which
one is used). No token prompt should appear now. Flip on 2–3 sources —
pick ones already confirmed (with the Machine C operator) to show a clear
contrast in Wazuh's dashboard.

**(wait)** Do not go to step 5 until the operator says the "before" shot has
been shown on Machine C's Wazuh dashboard.

## 5 · Phase 2 — switch the same traffic to ULPF instead

Stop the process from step 4 (Ctrl-C in that terminal). `--sim-target` is
read once at startup, so this needs a restart, not a live toggle. Fill in
Machine B's address:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target <<MACHINE_B_IP>>:5514 --no-auth
```

**(manual)** Open `http://localhost:8788/dev` again, flip the **same**
sources back on.

**(wait)** Machine B must already be running its collector (its step 2)
before this will show anything.

## 6 · Optional — add to the throughput/scale story

A second, independent stream at a measured rate, summed with Machine B's
own collector throughput when talking about progress toward 1B/day:

```powershell
.\target\release\ulpf.exe replay --source realdata\snort.log --target <<MACHINE_B_IP>>:5514 --eps 2000
```

## If something looks wrong

| Symptom | Likely cause |
|---|---|
| `/dev` page shows sources as "absent" | `realdata` wasn't fetched from this same folder, or `dir realdata` (step 3) came back empty |
| `serve` prints an `Error:` and exits immediately | Read the exact text — usually a port already in use, or `packs`/`realdata` not found because this isn't being run from the `ULPF` folder |
| Nothing arrives at Wazuh (`10.60.197.6`) | Confirm this machine can reach it at all first: `ping 10.60.197.6`. If that fails, it's a network/firewall problem, not a ULPF problem — fix connectivity before touching any command here again |
| `ping 10.60.197.6` works but nothing shows in Wazuh | Machine C's `ossec.conf` `<remote>` block may not be applied yet, or its `allowed-ips` subnet doesn't include this machine's address — check `demo-machine-c.md` steps 3–4 |
| Build fails: "output path is not a writable directory" | Windows ReadOnly attribute on this folder — run `attrib -r /s /d .` in the repo root |

Full narrative and the reasoning behind each step:
[3-LAPTOP-DEMO.md](3-LAPTOP-DEMO.md).
