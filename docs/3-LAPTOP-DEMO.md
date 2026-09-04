# Three-machine demonstration

A live demonstration on three networked machines: one generating real
perimeter-device traffic, one running ULPF, one receiving the normalized OCSF
events as a downstream SIEM would.

Every command in this document has been run against the current build. If a
command here does not work, that is a bug in this document — please report it.

> **Two machines also works.** Fold the sender onto the ULPF machine and point
> it at `127.0.0.1`. Everything except the physical network separation is
> identical. See [Two-machine variant](#two-machine-variant).

---

## What the three machines do

```
  MACHINE A  ──── UDP 5514 ────▶  MACHINE B  ──── HTTP 9200 ────▶  MACHINE C
  Log sources                    ULPF collector                   SIEM / data lake
  (replays real captures)        (normalizes, vaults,             (OpenSearch)
                                  attests, forwards)
                                        │
                                        └── operator console on :8787
```

| | Role | Needs |
|---|---|---|
| **A** | Replays real public captures over UDP syslog | ULPF binary, the corpora |
| **B** | Receives, vaults, normalizes to OCSF, attests, forwards | ULPF binary, the packs |
| **C** | Receives OCSF events, proves SIEM integration | Docker, or nothing (see below) |

Machine C is **optional**. Requirement (g) can be shown on machine B alone with
the Parquet sink, which needs no second host. Bring C only if you want a search
UI in the room.

---

## Before the day

### Network

All three on one switch or one hotspot. **No internet is required at demo time**
— that is the point of requirement (j). Note the addresses:

| Machine | Example address | Fill in yours |
|---|---|---|
| A — sources | `192.168.1.101` | |
| B — ULPF | `192.168.1.102` | |
| C — SIEM | `192.168.1.103` | |

On machine B, allow inbound **UDP 5514** and **TCP 8787**. On Windows:

```powershell
New-NetFirewallRule -DisplayName "ULPF syslog" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
New-NetFirewallRule -DisplayName "ULPF console" -Direction Inbound -Protocol TCP -LocalPort 8787 -Action Allow
```

On Linux:

```bash
sudo ufw allow 5514/udp comment "ULPF syslog"; sudo ufw allow 8787/tcp comment "ULPF console"
```

### Build, on every machine that runs ULPF (A and B)

Do this **while you still have internet**. The build needs to download crates
once; nothing after it does.

```bash
git clone https://github.com/D3v4nshPat3l/ULPF.git
```

```bash
cd ULPF && cargo build --release --locked
```

Confirm the build is sound:

```bash
cargo test --workspace --release --locked
```

```bash
./target/release/ulpf test --packs packs
```

Expect `18 packs · 37/37 fixtures passed · 100.0% field accuracy`.

> **Windows note.** If `cargo build` fails with
> `autocfg ... output path is not a writable directory`, the repository is
> inside a folder carrying the Windows *ReadOnly* attribute — `Documents`,
> `Pictures` and the other shell folders do. Clear it once:
> `attrib -r /s /d .` from the repository root.

### Fetch the corpora, on machine A

Also while you still have internet. Roughly 150 MB.

```bash
python tools/fetch_datasets.py
```

This writes ten corpora into `../realdata`, alongside the repository. They are
not committed: they are third-party data with their own terms, and vendoring
them would silently relicense it. See [DATASETS.md](DATASETS.md).

### Rehearse once, end to end, before the day

The single most common failure is a firewall rule that was never tested.

---

## Machine C — the SIEM (optional, set up first)

So it is already accepting writes when B starts forwarding.

```bash
cd ULPF && docker compose -f deploy/opensearch-compose.yaml up -d
```

Wait for it to answer, then confirm:

```bash
curl http://localhost:9200
```

OpenSearch Dashboards comes up on <http://localhost:5601>. After the first
events arrive, create an index pattern for `ulpf-events*`.

> This stack has security disabled and binds broadly. It is a **demonstration
> receiver on an isolated network**, not a deployment posture. Do not put it on
> a real one.

---

## Machine B — the ULPF collector

This is the machine the judges watch.

```bash
cd ULPF
```

```bash
./target/release/ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --chain demo --host 0.0.0.0 --port 8787 --syslog-bind 0.0.0.0:5514 --datasets ../realdata --opensearch http://192.168.1.103:9200 --opensearch-index ulpf-events
```

Substitute machine C's address. **Drop the two `--opensearch` arguments
entirely if you are not running machine C** — everything else works unchanged.

What each argument does:

| Argument | Why |
|---|---|
| `--host 0.0.0.0` | Console reachable from the other machines. Defaults to loopback only. |
| `--syslog-bind 0.0.0.0:5514` | UDP receiver. Change the port to run two collectors on one host. |
| `--chain demo` | Names the attestation chain. Resumes across restarts. |
| `--datasets ../realdata` | Where the simulator looks for corpora. Only needed if B also generates traffic. |
| `--opensearch` | Forwards each normalized event to the SIEM. |

On startup it prints the granted UDP receive buffer, the pack count and the
public key path. A line like `UDP receive buffer: 8192 KB` confirms the socket
was enlarged; a warning there means the host capped it, and sustained bursts
above a few thousand EPS may drop.

Open the console at **<http://192.168.1.102:8787>**.

> **The console has no authentication.** It is bound to `0.0.0.0` here only
> because three machines share an isolated demo network. Never expose it to a
> real network without a reverse proxy in front.

---

## Machine A — the log sources

Point the built-in replay at machine B. One command per source; run each in its
own terminal, or pick two or three.

```bash
./target/release/ulpf replay --source ../realdata/iptables.log --target 192.168.1.102:5514 --eps 2000
```

```bash
./target/release/ulpf replay --source ../realdata/snort.log --target 192.168.1.102:5514 --eps 500
```

```bash
./target/release/ulpf replay --source ../realdata/apache-access.log --target 192.168.1.102:5514 --eps 300
```

Add `--count 50000` to stop after a fixed number rather than looping.

### Or drive it from a browser

If machine A also runs `serve`, its `/dev` page gives you switches instead of
terminals — and streams keep running whether or not the page is open:

```bash
./target/release/ulpf serve --packs packs --vault data/simvault --integrity-dir data/simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets ../realdata --sim-target 192.168.1.102:5514
```

Then open **<http://localhost:8788/dev>** and flip sources on. Note the
different `--port` and `--syslog-bind`: machine A is running its own collector
purely to host the simulator, and it must not collide with B's ports.

`--sim-target` is where the simulator sends. It is a server-side flag, not a
field in the page.

---

## Running the demonstration

Roughly nine minutes. Each step demonstrates a lettered requirement from the
problem statement, so name them as you go.

### 1 · Heterogeneous input, one schema — (b) (c) (f)

Start two or three sources on A. On B's **Overview**, events fill in and
coverage settles near 100%. Point at the table: netfilter, Snort and Apache
arrive in three unrelated formats and leave as one OCSF schema. The IP
addresses are real — `11.11.79.x` is the Honeynet subnet, and the external
addresses are genuine scan traffic from the capture.

### 2 · Nothing is discarded — (a) (d)

Click any row. The drawer shows the vault locator, then **the original bytes
retrieved from the vault** and re-hashed. Say plainly: the raw bytes were
written to an append-only store *before* any parsing was attempted, and this
event carries a pointer back to them. Parsing cannot lose data because parsing
happens after preservation.

### 3 · Tamper evidence — the core claim

Go to **Integrity** and press **Run verification**: every event re-hashed,
every link intact, checkpoint signature valid.

Now **Tamper test**. Leave the defaults, press **Alter this event** — it names
the attribute and shows before and after. Verify again:

> `Chain verification FAILED — fingerprint mismatch: event content has been altered`

One field on one event out of hundreds, caught immediately. The vault is
untouched, so the original bytes remain retrievable and provably different from
the altered record.

You can also demonstrate this from a terminal, independently of the console:

```bash
./target/release/ulpf verify events.ndjson --checkpoint data/integrity/demo.checkpoint.json --public-key data/integrity/ed25519-signing.pub
```

### 4 · Onboarding an unknown device — (e) (i)

Paste an invented device format into **Event inspector** and normalize it. It
lands as *needs a pack* — still vaulted, still fingerprinted, still valid OCSF.

Go to **Needs a pack**: it has been clustered by template. Press **Heuristic**
— no model, no GPU, works air-gapped — and a candidate pack appears with its
fixture score. Read the detectors aloud, then **Approve and deploy**. The
filesystem watcher loads it within a second or two; send the same line again
and it now normalizes.

> Be straight about the score: fixtures are built from the same samples, so
> 100% means the draft is self-consistent, not that it generalizes. The console
> says so on that panel.

### 5 · Air-gapped — (j)

Unplug machine B from everything except the demo switch, or disable its
uplink. Everything above keeps working. The console's HTML, CSS and JavaScript
are compiled into the binary; there is no CDN, no web font, no telemetry, no
model API on the hot path.

### 6 · SIEM integration — (g)

On machine C, search `src_endpoint.ip: "11.11.79.89"`. One query returns
records that arrived as netfilter, as Snort and as Apache — because they left
ULPF as one schema. That is the whole argument for normalization, in one
search box.

Without machine C, add `--parquet data/parquet` to B's command line and show
the partitioned files instead.

---

## Two-machine variant

Machine A folds onto B. Run the collector:

```bash
./target/release/ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --host 127.0.0.1 --port 8787 --syslog-bind 127.0.0.1:5514 --datasets ../realdata --sim-target 127.0.0.1:5514
```

Open <http://127.0.0.1:8787/dev>, flip sources on, and watch
<http://127.0.0.1:8787>. Same demonstration, one less machine to go wrong.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Console shows nothing, sources say "sent N" | Datagrams are not arriving | Firewall on B, or wrong `--target`. Test with `ulpf replay --source ... --target <B>:5514 --eps 10 --count 10` and watch B's counter |
| Every source reads **absent** in `/dev` | Corpora not fetched, or wrong path | `python tools/fetch_datasets.py`, and check `--datasets` points at `../realdata` |
| `could not bind the console to ...` | Port already taken | Another `ulpf serve` is running, or pick another `--port` |
| Coverage well below 100% | Wrong corpus for the loaded packs | Expected for sources with no pack; check **Needs a pack** |
| Received count far below sent | UDP loss above the sustained rate | Lower `--eps`. See [THROUGHPUT.md](THROUGHPUT.md) — 10,000 EPS is the measured lossless ceiling per collector |
| Console unreachable from another machine | Bound to loopback | `--host 0.0.0.0` |
| Build fails, `output path is not a writable directory` | Windows ReadOnly attribute on a shell folder | `attrib -r /s /d .` in the repository root |

### Reset between rehearsals

Counters, vault and chain all persist deliberately. To start clean:

```bash
rm -rf data/vault data/integrity
```

**Clear view** in the console only empties the on-screen window — it advances
the verification anchor and leaves the vault and chain intact, which is why
verification still works afterwards.

---

## What to have ready

- Both machines built, tested, and **rehearsed on the actual demo network**
- Corpora fetched on A
- Firewall rules added *and verified*, not just added
- Browser open on B at the console, second tab on `/dev` if A is folded in
- A terminal on B for the independent `ulpf verify` run
- The addresses written down somewhere you can read them under pressure
