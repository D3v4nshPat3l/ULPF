# Demonstration — one laptop, start to finish

Every command here was executed on a single machine before it was written
down, and the outputs quoted are the ones it produced. Nothing needs a second
host or a model.

The centrepiece is section 2: **the same captured traffic sent to a real SIEM
twice — once raw, once through ULPF** — so the difference is visible rather
than asserted.

---

## Quickstart — launch everything

Four terminals, in this order. Full explanation of each step is below; this
block is the one to copy on demo day.

**Terminal 1 — the SIEM** (first run only: generate certificates)

```bash
cd deploy/wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps                 # wait until all three read "running"
```

**Terminal 2 — ULPF, with the forward leg to the SIEM turned on**

```bash
cargo build --release --locked
./target/release/ulpf serve \
  --packs packs \
  --vault data/vault \
  --integrity-dir data/integrity \
  --datasets realdata \
  --forward-udp 127.0.0.1:514 \
  --no-auth
```

**Terminal 3 — confirm both are up**

```bash
curl -s http://127.0.0.1:8787/readyz
docker exec single-node-wazuh.manager-1 sh -c 'ls -l /var/ossec/logs/archives/archives.json'
```

**Browser — the two pages you drive the demo from**

| | |
|---|---|
| ULPF simulator (the one-click switch) | <http://127.0.0.1:8787/dev> |
| ULPF console | <http://127.0.0.1:8787> |
| Wazuh dashboard | <https://localhost> — `admin` / `SecretPassword` |

**In Wazuh, once:** ☰ → *Dashboards Management* → *Index patterns* → *Create
index pattern* → name `wazuh-archives-*`, time field `timestamp` → Create.
Then ☰ → *Discover*, select `wazuh-archives-*`, time picker *Last 15 minutes*,
and add `full_log` as a column.

Without that index pattern the dashboard shows nothing and it looks like no
data arrived when it did. This is the single most common way this
demonstration appears broken.

Then drive it: **Wazuh** button in `/dev` → look at `full_log` → **ULPF**
button → look at `full_log` again. That is the whole comparison, and it is
section 2 below.

---

## 0. Prerequisites

| | |
|---|---|
| Rust | 1.85+ (pinned by `rust-toolchain.toml`) |
| Python | 3.9+, only for fetching corpora and reproducing measurements |
| Docker | only for section 2, the SIEM comparison |
| Disk | ~2 GB for the build |

```bash
cargo build --release --locked
./target/release/ulpf test --packs packs
```

```
35 packs · 75/75 fixtures passed · 100.0% field accuracy
```

Every Source Pack carries its own fixtures, so this is the packs testing
themselves. A pack that cannot parse its own sample lines never loads.

On Windows the binary is `target/release/ulpf.exe`; the commands below use the
Unix name.

---

## 1. Start ULPF

```bash
./target/release/ulpf serve \
  --packs packs \
  --vault data/vault \
  --integrity-dir data/integrity \
  --datasets realdata \
  --forward-udp 127.0.0.1:514
```

- Console: <http://127.0.0.1:8787>
- Traffic simulator: <http://127.0.0.1:8787/dev>
- UDP syslog intake: `0.0.0.0:5514`

`--forward-udp 127.0.0.1:514` is what makes section 2 work: every event ULPF
normalizes is also emitted as one OCSF datagram to the SIEM's syslog port.
Leave it off and ULPF simply keeps its output to itself.

The first run prints a console token once and stores it at
`data/integrity/console.token`. Paste it when the page prompts. Use
`--no-auth` for a throwaway local demo.

```bash
curl -s http://127.0.0.1:8787/readyz
```

```json
{"ready":true,"packs_loaded":35,"vault_writable":true,"chain_signed_or_empty":true,"schema_version":"1.9.0"}
```

Nothing on the page is fetched from the network — the HTML, CSS and
JavaScript are compiled into the binary. That is requirement (j),
demonstrable by pulling the network cable.

---

## 2. The comparison: the same traffic, twice

### 2a. Bring up the SIEM

A single-node Wazuh stack, on the same laptop.

> If anything below does not behave, do not debug it here.
> [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md) is the exhaustive version —
> WSL 2 and Docker Desktop setup, verifying the UDP 514 listener, proving
> archive storage and indexing, and a troubleshooting section organised by
> symptom. [`deploy/wazuh/README.md`](../deploy/wazuh/README.md) covers the
> stack itself.

```bash
cd deploy/wazuh
docker compose -f generate-indexer-certs.yml run --rm generator   # once per machine
docker compose up -d
```

Dashboard at <https://localhost> (`admin` / `SecretPassword`, self-signed
certificate — the browser warns once).

Create the index pattern **`wazuh-archives-*`** with time field `timestamp`,
via ☰ → Dashboards Management → Index patterns. Without it the dashboard shows
nothing and it looks like no data arrived, when it did.

> Wazuh indexes *alerts* by default, so a log no rule matches leaves no trace.
> The compose file here turns on `logall_json` archives precisely because a
> normalization demonstration is about ordinary traffic, not alerts.

### 2b. Send raw traffic straight to the SIEM

In <http://127.0.0.1:8787/dev>, press **Wazuh** in the target switch, and
switch on a few sources. The simulator's target becomes `127.0.0.1:514`, and
every enabled source replays a **real public capture** there.

In Discover, on `wazuh-archives-*`, look at `full_log`. What you see is the
vendor's own line, undigested:

```
%ASA-6-302013: Built inbound TCP connection 12345678 for outside:203.0.113.9/49221 to inside:192.0.2.5/443
Feb 25 12:21:33 bastion snort[1885]: [1:483:5] ICMP PING CyberKit 2.2 Windows [Priority: 3]: {ICMP} 70.81.243.88 -> 11.11.79.100
1756636800.123 152 10.2.4.7 TCP_MISS/200 12345 GET http://example.com/en/index.html
```

Three vendors, three unrelated shapes. There is no field to search on. An
analyst asking "show me everything involving 11.11.79.100" has to know all
three formats, and the other forty in the building.

### 2c. One click: the same traffic, through ULPF

Press **ULPF** in the same target switch. The simulator now sends to
`127.0.0.1:5514`, ULPF normalizes, and `--forward-udp` carries the result on
to the same Wazuh instance.

Same Discover view, same index. `full_log` now holds OCSF:

```json
{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,
 "src_endpoint":{"ip":"70.81.243.88"},"dst_endpoint":{"ip":"11.11.79.100"},
 "metadata":{"version":"1.9.0","log_provider":"snort-nids-alert",
             "product":{"vendor_name":"Snort","name":"Snort NIDS"}},
 "observables":[{"name":"src_endpoint.ip","type_id":2,"value":"70.81.243.88"}],
 "unmapped":{"ulpf_raw_locator":"ulpf:raw:0000000000000005:0000000000000000:0000009b"},
 "attestation_list":[{"chain_uid":"default","fingerprint":{"value":"5e5e2592…"}}]}
```

That one screen is the whole argument:

- **One schema.** Every vendor above is now `src_endpoint.ip`, queryable in a
  single expression.
- **Nothing lost.** `ulpf_raw_locator` points back at the exact original
  bytes, retrievable in section 4.
- **Tamper-evident.** Each event carries a fingerprint chained to its
  predecessor — section 5.
- **Nothing invented.** The records ULPF could not identify are still there,
  still searchable by indicator, and still marked as unidentified rather than
  guessed at.

---

## 3. What the console itself shows

Worth walking through on <http://127.0.0.1:8787> while traffic is flowing:

1. **Overview** — events received, OCSF coverage, vaulted bytes, chain
   sequence, and a live table naming which pack claimed each record.
2. **Raw logs** — every line fetched back *out of the vault* by locator, not
   echoed from the ingest path, with the fingerprint taken at ingest beside
   one recomputed from the bytes that just came back.
3. **Packs** — all 35 with their decoder chains and live fixture scores.
4. **Clusters** — unparsed records grouped into templates, each with a
   specificity score and an evidence-based source profile.
5. **Integrity** — re-hashes the retained window and walks the chain links.

---

## 4. Retrieve the original bytes of one event

```bash
./target/release/ulpf raw --vault data/vault \
  ulpf:raw:0000000000000000:0000000000000000:0000008b
```

```
CEF:0|Security|threatmanager|1.0|100|Network Event|4|src=10.0.0.29 dst=203.0.113.36 spt=49289 dpt=53 act=permit rt=1788370267774 proto=TCP
```

The exact input line, byte for byte, in one seek and one block decompress —
not a reconstruction from the normalized event. Requirement (a), and half of
(d), in one command.

---

## 5. Alter one field, and watch verification fail

The claim the project stands on, so do it live. Using a file run for
repeatability:

```bash
./target/release/ulpf run --packs packs \
  --vault data/vault --integrity-dir data/integrity \
  --input testdata/mixed.log --output events.ndjson
```

```
received 7319 · parsed 6740 (92.0891% coverage) · 18674 events/sec
```

> `testdata/mixed.log` is **synthetic and labelled as such**. It exists so the
> pipeline can be exercised without downloading corpora, and no published
> figure is ever measured on it.

Verify it:

```bash
./target/release/ulpf verify events.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
OK  7319 events verified
    signed checkpoint verified
    trusted public key verified
```

Now change one source IP out of 7,319 events:

```bash
python - <<'EOF'
import json, pathlib
p = pathlib.Path("events.ndjson")
lines = p.read_text(encoding="utf-8").splitlines()
d = json.loads(lines[100]); print("before:", d["src_endpoint"]["ip"])
d["src_endpoint"]["ip"] = "9.9.9.9"
lines[100] = json.dumps(d)
pathlib.Path("tampered.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
EOF

./target/release/ulpf verify tampered.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
[default] FAIL  fingerprint mismatch: event content has been altered
Error: 1 of 1 chains failed verification
```

The vault was not touched, so the original is still retrievable with section 4
and provably different from the altered record.

The console does the same thing live under **Tamper**, on a retained event.

---

## 6. Prove one event was logged, without disclosing the rest

```bash
head -1 events.ndjson > event.json
./target/release/ulpf prove \
  --integrity-dir data/integrity --chain default \
  --event event.json > proof.json
```

```
proof for event 1 of 7319: 13 hashes, 416 bytes
```

Verify holding nothing but the proof and a trusted public key — no vault, no
chain, no other event:

```bash
./target/release/ulpf verify-proof \
  --proof proof.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
PROOF VALID
  chain:            default
  position:         1 of 7319
  proof size:       13 hashes
  signed root:      f648dfa956aefebc608572358e51ea7208b40a6cd647f09b012c608ed2bc97ec

This record was in the log when the checkpoint was signed.
```

416 bytes proving one record out of 7,319, checkable by someone holding no
other part of the log. That is what makes an extract from a sensitive log
shareable.

---

## 7. Onboard a device ULPF has never seen

Every real corpus is already claimed by a shipped pack, so demonstrating
onboarding needs a genuinely unknown device:

```bash
python tools/make_demo_source.py
```

This writes a **fictional** appliance's logs — labelled synthetic in five
places, RFC 5737 documentation addresses throughout, and excluded by an
assertion in `tools/measure_coverage.py` so it can never enter a published
figure.

Then, in the console: switch the source on in `/dev`, watch it arrive in
**Clusters** as unparsed, and draft a pack from it with either generator —

- **Heuristic**: deterministic, no model, works air-gapped.
- **AI Copilot**: a local model via Ollama, if one is running.

Both are offered explicitly rather than one hiding behind the other's failure,
because a deployment that forbids an LLM still has to onboard new devices.

Review the candidate, edit it, approve. It hot-reloads and starts claiming
traffic immediately. Nothing activates without that approval, and approval
re-validates server-side — the editor cannot talk the collector into loading a
pack that fails its own fixtures.

---

## 8. Reproducing the published measurements

```bash
python tools/fetch_datasets.py          # every corpus; ~6 GB archives, ~65 GB on disk
python tools/measure_coverage.py        # the coverage table
python tools/measure_throughput.py      # sustained EPS, and the events/day projection
```

`measure_coverage.py` prefers the complete corpus for every source and tags a
row `[sample]` if it fell back to a 2,000-line excerpt, so a smaller number
cannot be mistaken for the real one.

`measure_throughput.py` reports the sustained lossless rate and multiplies it
by 86,400. That is arithmetic on a measured rate, labelled as such — never a
claim to have ingested that many records.
