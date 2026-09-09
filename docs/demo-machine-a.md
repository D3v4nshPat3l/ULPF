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

```powershell
ipconfig
```

Note the IPv4 address of the adapter connected to the shared hotspot. Tell
the other two machines this address if either needs it (Machine A is not
usually addressed by the others in this demo, but confirm).

## 2 · Build and verify (needs internet, once)

```powershell
git clone https://github.com/D3v4nshPat3l/ULPF.git
cd ULPF
cargo build --release --locked
cargo test --workspace --release --locked
.\target\release\ulpf.exe test --packs packs
```

Expect `35 packs · 75/75 fixtures passed · 100.0% field accuracy`. Do not
proceed to step 3 if this fails — fix the build first.

## 3 · Fetch the real log corpora (needs internet, once, ~150 MB)

```powershell
python tools/fetch_datasets.py
```

Writes into `realdata/`, next to this repo. Confirm it exists before
continuing:

```powershell
dir realdata
```

## 4 · Phase 1 — send real traffic into Wazuh directly

Fill in Machine C's (Wazuh's) address:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target <<WAZUH_IP>>:514
```

Leave this running.

**(manual)** Open `http://localhost:8788/dev` in a browser. Flip on 2–3
sources — pick ones already confirmed (with the Machine C operator) to show
a clear contrast in Wazuh's dashboard.

**(wait)** Do not go to step 5 until the operator says the "before" shot has
been shown on Machine C's Wazuh dashboard.

## 5 · Phase 2 — switch the same traffic to ULPF instead

Stop the process from step 4 (Ctrl-C in that terminal). `--sim-target` is
read once at startup, so this needs a restart, not a live toggle. Fill in
Machine B's address:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target <<MACHINE_B_IP>>:5514
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
| `/dev` page shows sources as "absent" | `realdata` wasn't fetched, or wrong `--datasets` path |
| Nothing arrives on the target | Wrong IP, or a firewall on the target machine blocking the port |
| Build fails: "output path is not a writable directory" | Windows ReadOnly attribute on this folder — run `attrib -r /s /d .` in the repo root |

Full narrative and the reasoning behind each step:
[3-LAPTOP-DEMO.md](3-LAPTOP-DEMO.md).
