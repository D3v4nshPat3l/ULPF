# Machine B — main dashboard / the real ULPF collector (Windows)

> **If you are an AI agent:** you are running on Machine B, one of three
> laptops in a live demo. Only execute commands in this file — Machine A's
> and Machine C's commands live in `demo-machine-a.md` and
> `demo-machine-c.md` and are not yours to run. Placeholders look like
> `<<THIS>>` — ask the human operator for the real value before running a
> command that contains one, unless they've already told you. Steps marked
> **(manual)** happen in a browser, not a terminal. Steps marked **(wait)**
> depend on another machine; do not proceed past one until the operator
> confirms it.

**What this machine does:** runs the real ULPF collector — the thing being
demonstrated — and its own OpenSearch destination. This is the machine
judges watch.

**You need:** this repo, a Rust toolchain, Docker Desktop, one internet
connection before step 2 (none after).

---

## 1 · Find this machine's address

```powershell
ipconfig
```

Note the IPv4 address of the adapter on the shared hotspot. Machine A needs
this address for its step 5; Machine C does not need it.

## 2 · Build and verify (needs internet, once)

```powershell
git clone https://github.com/D3v4nshPat3l/ULPF.git
cd ULPF
cargo build --release --locked
cargo test --workspace --release --locked
.\target\release\ulpf.exe test --packs packs
```

Expect `35 packs · 75/75 fixtures passed · 100.0% field accuracy`. Do not
proceed to step 3 if this fails.

## 3 · Stand up this machine's own OpenSearch stack

```powershell
docker compose -f deploy/opensearch-compose.yaml up -d
curl http://localhost:9200
```

Wait for a JSON response from that `curl` before continuing — the container
takes a few seconds to become ready.

> This stack has security disabled and binds broadly. Fine for an isolated
> demo hotspot; never expose it to a real network.

## 4 · Start the real collector

Uses this machine's own address from step 1:

```powershell
.\target\release\ulpf.exe serve --packs packs --vault data\vault --integrity-dir data\integrity --chain demo --host 0.0.0.0 --port 8787 --syslog-bind 0.0.0.0:5514 --datasets realdata --opensearch http://<<THIS_MACHINE_IP>>:9200 --opensearch-index ulpf-events
```

Leave it running. It prints a console token — note it.

**`git pull` and rebuild before this step, if not already done.** A real
bug (commit `1a2cd89`) used to make the console's own first page load fail
with a bare JSON 401 instead of showing the token prompt — pulling the fix
is what makes "paste the console token when prompted" below actually true
rather than a dead end.

Do **not** point `--opensearch` at Wazuh's address instead of this
machine's own — Wazuh's indexer needs HTTPS and username/password auth,
this sink only speaks plain HTTP with a bearer token, and it will not
authenticate. Keep the two destinations separate.

**(manual)** Open `http://<<THIS_MACHINE_IP>>:8787` in a browser — this is
the console judges watch. Paste the console token when prompted.

**(wait)** Nothing will appear here until Machine A starts sending — that's
expected, not a bug.

## 5 · Once Machine A has switched traffic here (its step 5)

**(manual)** In the browser, open
`http://<<THIS_MACHINE_IP>>:5601` — OpenSearch Dashboards. First time only:
create an index pattern for `ulpf-events*`. Then search across every
source in one query, e.g. by `src_endpoint.ip`.

## 6 · The integrity proof, independent of any dashboard

Take one event out of `data\vault` (or export one from the console) into
its own file, then:

```powershell
.\target\release\ulpf.exe prove --integrity-dir data\integrity --chain demo --event one-event.json > proof.json
.\target\release\ulpf.exe verify-proof --proof proof.json --checkpoint data\integrity\demo.checkpoint.json --public-key data\integrity\ed25519-signing.pub --event one-event.json
```

Expect `PROOF VALID … This record was in the log when the checkpoint was
signed.` — say plainly that this proves one record without exposing any
other event in the log.

## Stopping cleanly

Ctrl-C in the collector's terminal, and wait for:

```
Shutting down. Sealing outputs…
checkpoint    seq NNN
sinks         closed
```

before closing the terminal.

## If something looks wrong

| Symptom | Likely cause |
|---|---|
| Console shows nothing, Machine A says it sent records | Firewall on this machine blocking UDP 5514, or Machine A has the wrong IP |
| `docker compose` fails to reach `localhost:9200` | Give the container more time, or check `docker ps` for a crash-looping container |
| `could not bind the console` | Another `ulpf serve` already running, or the port is taken — pick a different `--port` |

Full narrative and the reasoning behind each step:
[3-LAPTOP-DEMO.md](3-LAPTOP-DEMO.md).
