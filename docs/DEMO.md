# Demonstration — one laptop, start to finish

Every command here was executed on a single machine before it was written
down, and the outputs quoted are the ones it produced. Nothing needs a second
host, a network, or a model.

Total time from a clean clone: about five minutes, plus the build.

---

## 0. Prerequisites

| | |
|---|---|
| Rust | 1.85+ (pinned by `rust-toolchain.toml`) |
| Python | 3.9+, only for fetching corpora and reproducing measurements |
| Disk | ~2 GB for the build; the corpora are optional for this walkthrough |

```bash
cargo build --release --locked
```

On Windows the binary is `target/release/ulpf.exe`; everywhere else it is
`target/release/ulpf`. The commands below are written with the Unix name.

---

## 1. Prove the build is sound

```bash
cargo test --workspace --release --locked
./target/release/ulpf test --packs packs
```

Expected:

```
35 packs · 75/75 fixtures passed · 100.0% field accuracy
```

Every Source Pack carries its own fixtures, so this is the packs testing
themselves rather than a separate suite asserting about them. A pack that
cannot parse its own sample lines never reaches the loaded list.

---

## 2. Normalize a file, end to end

`testdata/mixed.log` mixes eight vendor formats. It is **synthetic and
labelled as such** — it exists so the pipeline can be exercised without first
downloading corpora, and no published figure is ever measured on it.

```bash
./target/release/ulpf run \
  --packs packs \
  --vault data/vault \
  --integrity-dir data/integrity \
  --input testdata/mixed.log \
  --output events.ndjson
```

Produces:

```
─── ULPF run summary ───
  received          7319
  parsed            6740 (92.0891% coverage)
  unidentified      163
    of those, searchable  163 (100.0% carry an indicator or a named field)
  extract failed    416
  normalize failed  0
  bytes in          1711568
  elapsed           0.392s  (18674 events/sec)
  by pack:
    checkpoint-firewall                      317
    cisco-asa-network                        1091
    fortinet-fortigate-traffic               1459
    generic-cef-network                      577
    linux-iptables-firewall                  834
    modsecurity-waf-alert                    134
    paloalto-panos-traffic                   1103
    snort-nids-alert                         378
    squid-proxy-access                       635
    suricata-eve-alert                       212
  checkpoint        seq 7319 head 48ba9d290f64844d…
```

Two things worth pointing at in a demonstration:

- **Ten different vendors, one schema.** Every row above became OCSF 1.9.
- **"unidentified" is not "lost".** All 163 records nobody wrote a pack for
  still carry an indicator or a field name, so an analyst can search for them.
  They are vaulted, fingerprinted and chained like everything else.

---

## 3. Retrieve the original bytes of one event

Every emitted event carries a locator back into the vault at
`unmapped.ulpf_raw_locator`. Take one from `events.ndjson` and ask for it:

```bash
./target/release/ulpf raw --vault data/vault \
  ulpf:raw:0000000000000000:0000000000000000:0000008b
```

```
CEF:0|Security|threatmanager|1.0|100|Network Event|4|src=10.0.0.29 dst=203.0.113.36 spt=49289 dpt=53 act=permit rt=1788370267774 proto=TCP
```

That is the exact input line, byte for byte, retrieved in one seek and one
block decompress — not a reconstruction from the normalized event. This is
requirement (a) and half of (d), demonstrable in one command.

---

## 4. Verify the whole chain

```bash
./target/release/ulpf verify events.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
OK  7319 events verified
    chain head 01a08b55-a243-7653-ae3d-4c6d4b62fd6f fingerprint 48ba9d29…
    signed checkpoint verified
    trusted public key verified
```

Each event's fingerprint is recomputed from its own canonical form and each
link back to its predecessor is walked, then the head is bound to an
Ed25519-signed checkpoint.

---

## 5. Alter one field, and watch it fail

This is the claim the project stands on, so it is worth doing live rather than
describing. Change a single source IP in the emitted stream:

```bash
python - <<'EOF'
import json, pathlib
p = pathlib.Path("events.ndjson")
lines = p.read_text(encoding="utf-8").splitlines()
d = json.loads(lines[100])
print("before:", d["src_endpoint"]["ip"])
d["src_endpoint"]["ip"] = "9.9.9.9"
lines[100] = json.dumps(d)
pathlib.Path("tampered.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
EOF
```

```bash
./target/release/ulpf verify tampered.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
[default] FAIL  fingerprint mismatch: event content has been altered
Error: 1 of 1 chains failed verification
```

One byte changed in one field out of 7,319 events, and verification names the
failure. The vault was not touched, so the original is still retrievable with
step 3 and provably different from the altered record.

---

## 6. Prove one event was logged, without disclosing the rest

Take any single event out of the stream:

```bash
head -1 events.ndjson > event.json

./target/release/ulpf prove \
  --integrity-dir data/integrity --chain default \
  --event event.json > proof.json
```

```
proof for event 1 of 7319: 13 hashes, 416 bytes
```

Now verify it holding nothing but the proof and a trusted public key — no
vault, no chain, no other event:

```bash
./target/release/ulpf verify-proof \
  --proof proof.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
PROOF VALID
  chain:            default
  event uid:        01a08b55-a110-7431-8ccc-2989efe7e6f7
  position:         1 of 7319
  proof size:       13 hashes
  signed root:      f648dfa956aefebc608572358e51ea7208b40a6cd647f09b012c608ed2bc97ec

This record was in the log when the checkpoint was signed.
```

416 bytes proving one record out of 7,319, checkable by someone who holds no
other part of the log. That is what makes an extract from a sensitive log
shareable.

---

## 7. The operator console

```bash
./target/release/ulpf serve \
  --packs packs \
  --vault data/vault \
  --integrity-dir data/integrity \
  --datasets realdata
```

- Console: <http://127.0.0.1:8787>
- Traffic simulator: <http://127.0.0.1:8787/dev>
- UDP syslog intake: `0.0.0.0:5514`

The first run prints a console token once and stores it at
`data/integrity/console.token`. Paste it when the page prompts; it is kept in
that browser's `localStorage` afterwards. Pass `--no-auth` for a throwaway
local demo.

Readiness, which is also what the container's `HEALTHCHECK` calls:

```bash
curl -s http://127.0.0.1:8787/readyz
```

```json
{"ready":true,"packs_loaded":35,"vault_writable":true,"chain_signed_or_empty":true,"schema_version":"1.9.0"}
```

Nothing on the page is fetched from the network: the HTML, CSS and JavaScript
are compiled into the binary. That is requirement (j) — it works with no route
off the host.

### What to show, in order

1. **Overview** — events received, OCSF coverage, vaulted bytes, chain
   sequence, and a live table naming which pack claimed each record.
2. **`/dev` simulator** — switch on a few sources. Each replays a *real*
   public capture over UDP. A corpus not on disk reports `absent` and cannot
   be switched on; there is deliberately no fallback to invented data.
3. **Raw logs tab** — every line fetched back out of the vault by locator,
   with the fingerprint taken at ingest beside one recomputed from the bytes
   that just came back.
4. **Integrity** — re-hashes the retained window and walks the chain links.
5. **Tamper** — alter one attribute on one retained event, then verify again.
   The vault is untouched; only the console's copy changed.
6. **Clusters** — unparsed records grouped into templates, each with a
   specificity score and an evidence-based source profile.

---

## 8. Onboarding a device ULPF has never seen

Every real corpus is already claimed by a shipped pack, so demonstrating
onboarding needs a genuinely unknown device:

```bash
python tools/make_demo_source.py
```

This writes a **fictional** appliance's logs — labelled synthetic in five
places, using RFC 5737 documentation addresses, and excluded by an assertion
in `tools/measure_coverage.py` so it can never enter a published figure.

Then in the console: switch the source on in `/dev`, watch it land in
**Clusters** as unparsed, and draft a pack from it — with the **Heuristic**
generator, which is deterministic and needs no model, or with the **AI
Copilot** if Ollama is running locally. Review the candidate, edit it if you
want, and approve.

Nothing activates without that approval, and approval re-validates
server-side: the editor cannot talk the collector into loading a pack that
fails its own fixtures.

---

## 9. Reproducing the published measurements

```bash
python tools/fetch_datasets.py          # every corpus; ~6 GB archives, ~65 GB on disk
python tools/measure_coverage.py        # the coverage table
python tools/measure_throughput.py      # sustained EPS and the events/day projection
```

`measure_coverage.py` prefers the complete corpus for every source and tags a
row `[sample]` if it had to fall back to a 2,000-line excerpt, so a smaller
number can never be mistaken for the real one. `measure_throughput.py` reports
the sustained lossless rate and multiplies it by 86,400 — arithmetic on a
measured rate, labelled as such, never a claim to have ingested that many
records.
