# ULPF architecture

Universal Log Pre-processing Framework · SIH 2026 · PS 26156 · NTRO

ULPF is the normalization layer between perimeter-device telemetry and security
analytics. It receives opaque records, preserves them before interpreting them,
extracts source-specific fields, emits OCSF 1.9.0, and binds every normalized
event to its original bytes through a verifiable integrity chain. It is not a
SIEM: correlation, alerting and detection consume ULPF output downstream.

## Processing path

```text
receiver ─▶ raw vault ─▶ identify ─▶ decoder chain ─▶ OCSF mapping ─▶ attest ─▶ sinks
              │            │                              │                      │
              │            └─ no pack ─▶ salvage ─▶ dead letter ─▶ cluster ─▶ draft
              └─ constant-time retrieval by locator                              │
                                                          human approves ─▶ hot reload
```

**The order is a correctness property.** The vault append precedes parsing, and
a block is flushed before any event carrying its locator is emitted. A record
that is unknown, malformed, or crashes a decoder is still stored, fingerprinted,
chained and emitted as valid OCSF. "Unparsed" is a routing decision, never data
loss.

## Components

| Crate | Responsibility |
|---|---|
| `ulpf-core` | Receipt envelope, transport, borrowed field map, raw locator, disposition |
| `ulpf-vault` | Append-only zstd-block archive, O(1) retrieval, crash recovery |
| `ulpf-decode` | Ten decoders (syslog RFC 3164/5424, CEF, LEEF, JSON, XML, CSV, key-value, regex) plus salvage extraction |
| `ulpf-pack` | Source Pack schema, validation, compilation, fixtures, scoring |
| `ulpf-ocsf` | OCSF event model, RFC 8785 canonicalization, hash chain, checkpoints, RFC 6962 Merkle log |
| `ulpf-generator` | Drain clustering, deterministic generator, local-model client, scorer |
| `ulpf-cli` | Ingestion, sinks, verification, proofs, embedded console |

## Raw vault — requirement (a)

Records are length-prefixed, batched into ~1 MiB zstd blocks, rotated into
segments. Each block header carries its coordinates, lengths and a CRC-32; the
reader re-validates it before trusting the segment index, so a corrupt index
cannot return wrong bytes. The index is an optimisation, not the source of
truth — a segment whose writer was killed is rebuilt by scanning block headers,
so a crash costs the tail block, not the archive. `RawRef(segment, offset, len)`
serialises as `ulpf:raw:<seg>:<off>:<len>` and travels on every event at
`unmapped.ulpf_raw_locator`.

## Source Packs — requirements (b), (c), (e)

A pack is one YAML file: identity detectors, an ordered decoder chain, OCSF
field mappings, enum translations, provenance, and golden fixtures. Packs
compile once at load; the hot path performs no network or model call per event.
A filesystem watcher recompiles the library on change, so onboarding a device is
dropping in a file — no restart, no rebuild. A pack that fails to compile is
logged and skipped while the previous library stays in service.

Validation rejects unknown fields, empty detectors, missing base mappings,
invalid enum references and framework-owned paths. Fixtures run in CI, and
`tools/audit_pack_enums.py` checks every `activity_id` against the vendored
schema — a pack can pass its own fixtures and still map a vendor's verb to the
wrong OCSF enum, which fixtures cannot catch.

## Unknown sources — requirements (i), and the Current Scope sentence

Two mechanisms, both deterministic.

**Salvage extraction** runs on any record no pack claims. It recovers addresses,
ports, MAC addresses, URLs, email addresses and hostnames from arbitrary text
into OCSF `observables`, so a device nobody has onboarded is still searchable by
the indicators an investigation pivots on. It deliberately populates only
`observables`: it reports that an address is present, never that it is the
source, because a wrong `src_endpoint.ip` is worse than an absent one.

**Assisted onboarding** clusters dead letters into templates ranked by volume,
then drafts a candidate pack — deterministically, or from a local model asked
only for recognition while Rust assembles the structure. Candidates are scored
against fixtures built from real samples, carry provenance, load below every
reviewed pack, and activate only on human approval.

## Integrity — requirement (d), and the Blockchain theme

Every event carries the OCSF `record_integrity` profile. Its fingerprint covers
the canonical (RFC 8785) event including its predecessor link and excluding only
its own fingerprint, so altering event *N* invalidates every event after it.
Ed25519 checkpoints sign the chain head periodically rather than per event —
OCSF has nowhere to carry per-event signature bytes, and signing each event
would cost more than the entire throughput budget.

Each checkpoint also signs a Merkle tree head over the event fingerprints, built
to RFC 6962 with `0x00`/`0x01` domain separation. The chain gives sequential
tamper-evidence at write time; the tree gives selective proof at read time. An
inclusion proof shows one record was logged in `⌈log₂ n⌉` hashes, verified by a
party holding no other part of the log — which is what makes an extract from a
sensitive log shareable. Consistency proofs bridge an older tree size to the
current signed root, and fail if the log was rewritten rather than extended.

## Outputs and deployment

NDJSON by default; Parquet, a fixed-contract feature table, OpenSearch Bulk and
Splunk HEC as fan-out (g, h). The console and its assets are compiled into the
binary, so there is no runtime network dependency of any kind — requirement (j),
proved in CI by running every build and test step `--offline`. Requirement (k)
is a two-stage build onto distroless, read-only root, all capabilities dropped.

## Limits

- **One collector sustains 10,000 EPS lossless.** Reaching billions/day is a
  sharded deployment: chains are per-collector and verify independently.
- **The console requires a bearer token by default** (`crate::auth`), on
  every `/api/*` route, plus an Origin/Host guard for browser-specific
  attacks the token does not cover (see the comment on `same_origin_only`).
  `--no-auth` disables the token check for a throwaway demo — with it set,
  the Origin/Host guard is the only remaining control, and it is browser
  safety, not a login: anyone who reaches the port directly can still act as
  the operator.
- **Console TLS is optional, off by default.** `--tls-self-signed` or
  `--tls-cert`/`--tls-key` terminate HTTPS at the console; plain HTTP is the
  default on the `127.0.0.1`-only case, where the traffic never leaves the
  host.
- **UDP syslog only.** TCP/TLS (RFC 5425) is future work; the receive buffer is
  raised at bind, but UDP has no backpressure. Console TLS does not extend to
  this path — it is a separate listener with its own transport.
- **Sinks use plain HTTP** to a trusted local endpoint; TLS termination is a
  deployment responsibility.
- **The vault and the signing key are protected by filesystem permissions,
  not encryption.** Anyone with read access to `--vault`/`--integrity-dir` on
  disk can read raw log content and, if the signing key's permissions were
  ever loosened, forge new checkpoints. Encryption at rest is tracked
  separately from these transport-layer changes.
- **Decoders read text.** Binary telemetry (NetFlow/IPFIX, EVTX) needs a second
  decoder contract taking `&[u8]`, not another pack.
