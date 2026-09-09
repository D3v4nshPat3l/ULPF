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

Expect `35 packs · 75/75 fixtures passed · 100.0% field accuracy`.

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

This writes ten corpora into `realdata`, alongside the repository. They are
not committed: they are third-party data with their own terms, and vendoring
them would silently relicense it. See [DATASETS.md](DATASETS.md).

### Rehearse once, end to end, before the day

The single most common failure is a firewall rule that was never tested.

---

## Wazuh comparison variant — this team's actual setup, commands included

Everything else in this document has been run against the current build.
**The Wazuh commands below have not** — Wazuh's exact config syntax and
default ports do shift between releases, so treat every command here as a
strong draft, run it once end to end before showing it to a judge, and fix
this document if a command differs on the installed version. That is
exactly the standard the rest of this file holds itself to.

**Setup this is written for:** three machines on one Wi-Fi hotspot.

| Machine | Role | OS |
|---|---|---|
| **A — "dev dashboard"** | Generates realistic multi-device traffic | Windows |
| **B — "main dashboard"** | Runs the real ULPF collector + its own OpenSearch stack | Windows |
| **C — Wazuh** | Already installed, reachable from Windows | Ubuntu Server |

**The technical constraint that shapes this whole plan:** ULPF's
`--opensearch` sink deliberately speaks plain HTTP with a bearer token only
(see [SINKS.md](SINKS.md) — there is a unit test that rejects an `https://`
URL). Wazuh's own indexer needs HTTPS plus username/password auth. **Do not
point `--opensearch` at Wazuh's indexer** — it will not authenticate. Instead
Wazuh gets its own independent raw feed over syslog, and ULPF forwards to
its *own* OpenSearch stack. Two dashboards, side by side, never one feeding
the other.

### 0 · Addresses

Hotspot IPs first — get these before anything else, they go into every
command below.

```powershell
# On A and B (Windows), in PowerShell:
ipconfig
```

Look for the adapter connected to the hotspot (often named "Wi-Fi" or
"Local Area Connection* n") and note its IPv4 address.

```bash
# On C (Ubuntu):
ip -4 addr show | grep inet
```

| Machine | Address | Fill in yours |
|---|---|---|
| A — dev dashboard | `192.168.137.101` | |
| B — main dashboard | `192.168.137.102` | |
| C — Wazuh | `192.168.137.103` | |

Confirm all three can reach each other before touching config:

```powershell
# From A and B
ping <Wazuh IP>
```

```bash
# From C
ping <machine B IP>
```

### 1 · Point Wazuh at incoming syslog — on C (Ubuntu)

Wazuh's manager needs a `<remote>` block to accept syslog from other hosts;
a stock install only listens for its own registered agents, not arbitrary
syslog senders.

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this block inside `<ossec_config>...</ossec_config>`, alongside
whatever is already there:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.137.0/24</allowed-ips>
</remote>
```

Use the actual hotspot subnet for `allowed-ips`, not `0.0.0.0/0` — this
opens an unauthenticated syslog listener, which is fine on an isolated
hotspot for a demo and wrong anywhere else.

By default Wazuh only turns logs that match one of its own decoding rules
into an alert — an unmatched raw line can simply not appear anywhere in the
dashboard, which would make the "before" shot look empty rather than messy.
Turn on full archiving so every arrival is visible regardless of whether
Wazuh's own rules understood it:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside `<global>...</global>`, set:

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Restart the manager and confirm it is actually listening:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo ss -ulnp | grep 514
```

Open the firewall if one is active:

```bash
sudo ufw allow 514/udp
sudo ufw allow from 192.168.137.0/24 to any port 514 proto udp
```

### 2 · Before — raw traffic straight into Wazuh, no ULPF involved

On **A** (Windows), run ULPF's own simulator, pointed at Wazuh:

```powershell
cd ULPF
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target 192.168.137.103:514
```

Open `http://localhost:8788/dev` and flip on two or three sources.

On **C**, watch it arrive as it's happening, independent of the dashboard:

```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

Then open Wazuh's dashboard (`https://192.168.137.103` — confirm the exact
port on this install; recent Wazuh serves it over HTTPS on 443) and look
under **Threat Hunting → Discover**, selecting the archives index if
**Alerts** looks sparse. Expect an inconsistent picture: some fields
present, most vendor-specific structure absent, nothing sharing one schema,
and no equivalent anywhere of "prove this one record is genuine without
showing the rest of the log."

**Pick the source shown here deliberately, ahead of time.** Test two or
three of the `realdata` corpora against Wazuh before the room is watching,
and use whichever shows the clearest gap — do not discover live which one
makes the point.

### 3 · Stand up ULPF's own destination — on B (Windows)

Needs Docker Desktop running.

```powershell
cd ULPF
docker compose -f deploy/opensearch-compose.yaml up -d
curl http://localhost:9200
```

Then the real collector, forwarding to that stack:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\vault --integrity-dir data\integrity --chain demo --host 0.0.0.0 --port 8787 --syslog-bind 0.0.0.0:5514 --datasets realdata --opensearch http://192.168.137.102:9200 --opensearch-index ulpf-events
```

Open `http://192.168.137.102:8787`, note the printed console token.

### 4 · Switch — same traffic, now through ULPF

Stop machine A's simulator (Ctrl-C) and restart it with a new target —
`--sim-target` is read once at startup, not adjustable live from the page:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\simvault --integrity-dir data\simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target 192.168.137.102:5514
```

Open `http://localhost:8788/dev` again, flip the **same** sources back on.

### 5 · After

On B's console (`:8787`), the same devices now arrive as one OCSF schema.
Click through to OpenSearch Dashboards (`http://192.168.137.102:5601` —
confirm the port `opensearch-compose.yaml` actually publishes) and search
across every source in one query. Then run the proof, independent of both
dashboards:

```powershell
.\target\release\ulpf.exe prove --integrity-dir data\integrity --chain demo --event one-event.json > proof.json
.\target\release\ulpf.exe verify-proof --proof proof.json --checkpoint data\integrity\demo.checkpoint.json --public-key data\integrity\ed25519-signing.pub --event one-event.json
```

Say the difference out loud rather than leaning on Wazuh looking bad on a
format it happens to parse poorly — that argument is fragile if Wazuh's
decoder for that particular vendor turns out to be decent. The argument
that doesn't depend on luck: Wazuh has no raw-byte vault and no way to prove
one record's authenticity without exposing every other record around it.
ULPF does both, independent of how good anyone's field-parsing is.

### 6 · Combine with the scale story

While the before/after is on screen, start one or two more independent
replays at their own sustained rate — either a second `ulpf serve`
instance on a spare port, or `ulpf replay` directly at B if a third machine
isn't available:

```powershell
.\target\release\ulpf.exe replay --source realdata\snort.log --target 192.168.137.102:5514 --eps 2000
```

Add up each collector's own measured EPS and say the sum plainly, as a sum
of independent per-collector chains — not one collector measured three
times.

### Before doing this in front of a judge

- Run steps 1–5 once, fully, today — not the morning of judging.
- Confirm the dashboard port (443 vs something else) and the exact
  `<remote>` syntax against the Wazuh version actually installed; both
  have changed across releases, and this document cannot know which one
  is on that Ubuntu box.
- Decide which corpus makes the clearest "before" in advance (see step 2).
- Have the plain two-machine, OpenSearch-only demo (below) ready as a
  fallback if the Wazuh leg isn't solid by showtime.

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
./target/release/ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --chain demo --host 0.0.0.0 --port 8787 --syslog-bind 0.0.0.0:5514 --datasets realdata --opensearch http://192.168.1.103:9200 --opensearch-index ulpf-events
```

Substitute machine C's address. **Drop the two `--opensearch` arguments
entirely if you are not running machine C** — everything else works unchanged.

What each argument does:

| Argument | Why |
|---|---|
| `--host 0.0.0.0` | Console reachable from the other machines. Defaults to loopback only. |
| `--syslog-bind 0.0.0.0:5514` | UDP receiver. Change the port to run two collectors on one host. |
| `--chain demo` | Names the attestation chain. Resumes across restarts. |
| `--datasets realdata` | Where the simulator looks for corpora. Only needed if B also generates traffic. |
| `--opensearch` | Forwards each normalized event to the SIEM. |

On startup it prints the granted UDP receive buffer, the pack count and the
public key path. A line like `UDP receive buffer: 8192 KB` confirms the socket
was enlarged; a warning there means the host capped it, and sustained bursts
above a few thousand EPS may drop.

Open the console at **<http://192.168.1.102:8787>**. It prints a console
token at startup — paste it into the browser prompt once, or use it directly
with `curl -H "Authorization: Bearer <token>" ...`.

> **Bound to `0.0.0.0` here only because three machines share an isolated
> demo network.** The token check stops an unauthenticated client from
> reaching `/api/*`, but add `--tls-self-signed` (or a real cert with
> `--tls-cert`/`--tls-key`) too if this network is anything other than a
> throwaway lab segment — plain HTTP means the token itself crosses the wire
> unencrypted. Never expose this to a real network without both.

---

## Machine A — the log sources

Point the built-in replay at machine B. One command per source; run each in its
own terminal, or pick two or three.

```bash
./target/release/ulpf replay --source realdata/iptables.log --target 192.168.1.102:5514 --eps 2000
```

```bash
./target/release/ulpf replay --source realdata/snort.log --target 192.168.1.102:5514 --eps 500
```

```bash
./target/release/ulpf replay --source realdata/apache-access.log --target 192.168.1.102:5514 --eps 300
```

Add `--count 50000` to stop after a fixed number rather than looping.

### Or drive it from a browser

If machine A also runs `serve`, its `/dev` page gives you switches instead of
terminals — and streams keep running whether or not the page is open:

```bash
./target/release/ulpf serve --packs packs --vault data/simvault --integrity-dir data/simintegrity --port 8788 --syslog-bind 127.0.0.1:5515 --datasets realdata --sim-target 192.168.1.102:5514
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


**Then prove one event without showing the others.** This is the part that has
no equivalent in the tools NTRO already runs. Take any single normalized event
from `events.ndjson` into its own file and prove it:

```bash
./target/release/ulpf prove --integrity-dir data/integrity --chain demo --event one-event.json > proof.json
```

It prints something like `proof for event 412 of 20000: 15 hashes, 480 bytes`.
Now verify it the way a recipient outside this room would — handing over only
`proof.json`, the checkpoint, and the public key. No vault, no chain, no other
event:

```bash
./target/release/ulpf verify-proof --proof proof.json --checkpoint data/integrity/demo.checkpoint.json --public-key data/integrity/ed25519-signing.pub --event one-event.json
```

> `PROOF VALID … This record was in the log when the checkpoint was signed.`

Say what that means plainly: an auditor, a court or a partner agency can be
shown that one record is genuine and was logged when it claims, while learning
nothing about the rest of the log. That is what makes evidence drawn from a
classified source shareable at all.

If the collector has kept running since the proof was made, `verify-proof` will
say the log has grown and print the two commands to bridge it. That is worth
letting happen on purpose — it demonstrates that the tree cannot quietly be
rewritten under an old proof:

```bash
./target/release/ulpf consistency --integrity-dir data/integrity --chain demo --from <tree_size from proof.json> > bridge.json
./target/release/ulpf verify-proof --proof proof.json --checkpoint data/integrity/demo.checkpoint.json --public-key data/integrity/ed25519-signing.pub --consistency bridge.json
```

### 4 · Onboarding an unknown device — (e) (i)

Paste an invented device format into **Event inspector** and normalize it. It
lands as *needs a pack* — still vaulted, still fingerprinted, still valid OCSF.

Point at its `observables` before moving on. Even with no pack, ULPF has pulled
the addresses, ports and hostnames out of a format it has never seen, so the
record is already searchable by the things an investigation pivots on. That is
the honest answer to "what happens to a device nobody has onboarded", and it
happens with no model and no network.

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
./target/release/ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --host 127.0.0.1 --port 8787 --syslog-bind 127.0.0.1:5514 --datasets realdata --sim-target 127.0.0.1:5514
```

Open <http://127.0.0.1:8787/dev>, flip sources on, and watch
<http://127.0.0.1:8787>. Same demonstration, one less machine to go wrong.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Console shows nothing, sources say "sent N" | Datagrams are not arriving | Firewall on B, or wrong `--target`. Test with `ulpf replay --source ... --target <B>:5514 --eps 10 --count 10` and watch B's counter |
| Every source reads **absent** in `/dev` | Corpora not fetched, or wrong path | `python tools/fetch_datasets.py`, and check `--datasets` points at `realdata` |
| `could not bind the console to ...` | Port already taken | Another `ulpf serve` is running, or pick another `--port` |
| Coverage well below 100% | Wrong corpus for the loaded packs | Expected for sources with no pack; check **Needs a pack** |
| Received count far below sent | UDP loss above the sustained rate | Lower `--eps`. See [THROUGHPUT.md](THROUGHPUT.md) — 10,000 EPS is the measured lossless ceiling per collector |
| Console unreachable from another machine | Bound to loopback | `--host 0.0.0.0` |
| Build fails, `output path is not a writable directory` | Windows ReadOnly attribute on a shell folder | `attrib -r /s /d .` in the repository root |
| A command rejects a flag the docs show, or a feature behaves as though it is missing | `target/release/ulpf` is older than the checkout | `cargo test` does not refresh it. Run `cargo build --release --locked` after every pull |

### Stopping the collector

Ctrl-C. It signs a final checkpoint for anything received since the last
periodic one and closes any Parquet writers, printing:

```
  Shutting down. Sealing outputs…
  checkpoint    seq 283
  sinks         closed
```

Wait for those lines before closing the terminal. If you are writing a feature
table with `--features`, that is the moment the file becomes readable — killing
the process instead leaves it without a Parquet footer, and pyarrow will refuse
it. The events survive either way; only the current table file does not.

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
