# ULPF Codebase — Complete File-by-File Analysis

> This document describes **every file and folder** in the repository as it stands on `main` after the merge. Nothing is left out.

---

## Repository Root

| File | Purpose |
|---|---|
| [Cargo.toml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/Cargo.toml) | Workspace manifest. Declares 7 crates, pinned workspace deps (serde, blake3, ed25519-dalek, winnow, etc.), release profile with LTO. |
| [Cargo.lock](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/Cargo.lock) | Lockfile. ~37 KB, all deps resolved. |
| [Dockerfile](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/Dockerfile) | Two-stage build: `rust:1.85-bookworm` builder → `debian:bookworm-slim` runtime. Copies the single `ulpf` binary and packs. Runs as non-root user `ulpf`. Exposes 8787 and 5514/udp. |
| [compose.yaml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/compose.yaml) | Single-service Docker Compose. Read-only filesystem, `no-new-privileges`, caps dropped. Mounts a named volume for vault data. |
| [rust-toolchain.toml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/rust-toolchain.toml) | Pins the Rust toolchain version. |
| [rustfmt.toml](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/rustfmt.toml) | Formatter config. |
| `simulate_traffic.ps1` / `.py` | **Our additions.** PowerShell and Python scripts that POST fake log lines to `/api/ingest` in a loop to simulate live traffic. |

---

## `packs/` — Source Pack Library (5 packs)

| Pack File | Vendor / Product | Decoder Chain |
|---|---|---|
| `fortinet-fortigate-traffic.yaml` | Fortinet / FortiGate | syslog → keyvalue |
| `paloalto-panos-traffic.yaml` | Palo Alto / PAN-OS | syslog → csv |
| `linux-iptables-firewall.yaml` | Linux / iptables | syslog → keyvalue |
| `generic-cef-network.yaml` | Generic / CEF | cef |
| `snort-nids-alert.yaml` | Snort / Snort IDS | syslog → regex |

Each YAML pack carries: `identity` (vendor, product, detectors), `extract` (decoder chain), `map` (field → OCSF path), `fixtures` (test cases with expected output).

---

## `crates/ulpf-core` — Core Types (3 files, ~1,050 LOC)

### [lib.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-core/src/lib.rs) — 302 lines
The spine of the pipeline. Defines:
- **`Transport`** enum — how a log arrived (SyslogUdp, SyslogTcp, SyslogTls, File, Http, Kafka, Stdin)
- **`Envelope`** — receipt metadata (timestamp, peer IP, transport, receiver_id, origin)
- **`RawEvent`** — the exact bytes received + their envelope
- **`RawRef`** — a durable pointer into the vault (segment, offset, length) with hex locator encoding `ulpf:raw:XXXX:XXXX:XXXX`
- **`Disposition`** — outcome enum (Parsed, Unidentified, ExtractFailed, NormalizeFailed)
- 5 unit tests covering locator round-trips, sort order, UTF-8 rejection

### [field.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-core/src/field.rs) — 357 lines
- **`Value<'a>`** — borrowed-first enum (Str(Cow), Int, Float, Bool, Null). Coerces device-style strings ("443" → int, "yes" → bool, "N/A" → absent).
- **`FieldMap<'a>`** — insertion-ordered Vec-backed map. Linear scan by design (device events have tens of fields). Supports merge-without-clobbering for decoder chains.
- 7 unit tests

### [error.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-core/src/error.rs) — 31 lines
Shared `Error` type: `BadLocator`, `LocatorField`, `FieldType`, `MissingField`, `Io`, `Json`.

---

## `crates/ulpf-decode` — Built-in Decoders (7 files, ~3,300 LOC)

### [lib.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/lib.rs) — 129 lines
- **`Decoder` trait** — `name()` + `decode(&str) → Decoded` (fields + optional inner body)
- **`builtin(name)` factory** — resolves `"syslog"`, `"keyvalue"`, `"csv"`, `"cef"`, `"json"`, `"regex"` to concrete decoder instances
- `BUILTIN_NAMES` constant listing all 8 decoder names

### Individual Decoders:
| File | Lines | Format | Notes |
|---|---|---|---|
| [syslog.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/syslog.rs) | 600+ | RFC 3164 & 5424 | Hand-written `winnow` state machine. Extracts PRI, timestamp, hostname, appname, PID, msgid. Returns body for the next decoder. |
| [keyvalue.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/keyvalue.rs) | 280+ | `key=value` pairs | Handles quoted values, configurable separator and delimiter. Used by FortiGate, iptables. |
| [cef.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/cef.rs) | 310+ | Common Event Format | Parses `CEF:0|vendor|product|version|...` header, then extension key=value. |
| [csv.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/csv.rs) | 300+ | Delimited columns | Configurable delimiter, quoting, column names. Used by PAN-OS. |
| [json.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/json.rs) | 180+ | JSON objects | Flattens nested JSON to dotted keys. |
| [regex_dec.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-decode/src/regex_dec.rs) | 270+ | Named capture groups | Pack supplies patterns; decoder applies them. Used by Snort. |

**Missing from the plan:** XML and LEEF decoders are mentioned in the build plan but **not implemented**.

---

## `crates/ulpf-ocsf` — OCSF v1.9.0 Model (5 files, ~3,800 LOC)

### [lib.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/lib.rs) — 65 lines
Re-exports. Declares event class constants: `NETWORK_ACTIVITY (4001)`, `HTTP_ACTIVITY (4002)`, `DNS_ACTIVITY (4003)`, `SSH_ACTIVITY (4007)`, `AUTHENTICATION (3002)`, `DETECTION_FINDING (2004)`. Activity IDs for Network Activity.

### [event.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/event.rs) — 510 lines
- **`OcsfEvent`** — wrapper around `serde_json::Map`. Dynamic by design (88 event classes through one code path).
- **`EventBuilder`** — enforces 5 required OCSF base attributes (`class_uid`, `activity_id`, `time`, `severity_id`, `metadata`). Derives `type_uid` and `category_uid` automatically.
- `set_path()` — creates nested JSON objects from dotted paths ("src_endpoint.ip")
- `set_unmapped()` — preserves extracted fields that have no OCSF home
- `canonical_bytes()` — RFC 8785 JCS serialization for hashing
- 10 unit tests

### [integrity.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/integrity.rs) — 805 lines
This is **the crown jewel** — the `record_integrity` profile implementation.
- **`Attestor`** — stamps each event with a BLAKE3/SHA-256 fingerprint and a backward link to the previous event, forming a hash chain
- **`Checkpoint`** — periodically Ed25519-signs the chain head
- **`verify_event()`** — strips fingerprint, re-hashes, compares
- **`verify_chain()`** — walks a chain checking every link
- **`verify_checkpoint()`** — binds a chain to a signed checkpoint
- 12 unit tests covering: tampering detection (field change, raw data change), chain deletion, reordering, checkpoint forging, wrong key, chain resume across restart, BLAKE3 round-trip

### [jcs.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/jcs.rs) — ~400 lines
RFC 8785 JSON Canonicalization Scheme. Deterministic serialization for hashing.

### [types.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-ocsf/src/types.rs) — ~470 lines
OCSF type definitions: `Metadata`, `Product`, `Attestation`, `PrevEvent`, `Fingerprint`, `DigitalSignature`, `Observable`, `Severity`, `StatusId`, `HashAlgorithm`.

---

## `crates/ulpf-vault` — Raw Vault (5 files, ~2,500 LOC)

- **`VaultWriter`** — append-only, zstd-compressed segment files. Returns `RawRef` for each append.
- **`VaultReader`** — retrieves exact original bytes by `RawRef`.
- **`format.rs`** — segment file format with length-prefixed records.
- Requirement (a) satisfied: bytes are preserved before any interpretation.

---

## `crates/ulpf-pack` — Source Pack System (6 files, ~4,200 LOC)

### [lib.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/lib.rs) — ~300 lines
**`Pack`** struct — the deserialized YAML. Contains identity, extract plan, OCSF map, fixtures, provenance.
**`PackLibrary`** — loads all `.yaml` files from a directory, compiles them, and provides `identify()` → match a raw line to a pack.

### [compiled.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/compiled.rs) — ~650 lines
**`CompiledPack`** — resolves decoder names to concrete decoder instances, compiles regex patterns, validates the extraction plan. This is what runs per-event.
- `identify()` — runs detectors (contains-all, transport match)
- `extract()` — runs the decoder chain, producing a `FieldMap`
- `normalize()` — maps extracted fields to OCSF paths using the `map` section

### [spec.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/spec.rs) — ~360 lines
Serde structures for the YAML pack format: `Identity`, `Detector`, `ExtractStep`, `MapSpec`, `Fixture`, `Provenance`.

### [library.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/library.rs) — ~430 lines
**`PackTestReport`** — runs fixtures, counts passed/failed, computes field accuracy. This is what powers `ulpf pack test`.

### [time.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-pack/src/time.rs) — ~200 lines
Timestamp parsing: epoch seconds, epoch millis, ISO 8601, common device date formats.

---

## `crates/ulpf-generator` — AI Generator (4 files, ~200 LOC)

### [lib.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-generator/src/lib.rs) — 4 lines
Just re-exports `drain`, `llm`, `scorer`.

### [drain.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-generator/src/drain.rs) — 113 lines
Drain clustering: tokenizes log lines, matches by token count and similarity threshold (0.4), creates `<*>` wildcard templates. Returns `ranked_clusters()` sorted by volume. Collects up to 30 samples per cluster.

### [llm.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-generator/src/llm.rs) — 69 lines
**Mocked.** `GeneratorClient::draft_pack()` returns a hard-coded YAML template. The struct and request/response types for `llama.cpp` are defined but the HTTP call is not actually made.

### [scorer.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-generator/src/scorer.rs) — 21 lines
`Scorer::score()` compiles a `Pack` into a `CompiledPack` and runs `test_pack()` against its fixtures.

---

## `crates/ulpf-cli` — CLI Binary (7 files + UI, ~5,500 LOC)

### [main.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/main.rs) — 853 lines
The `ulpf` binary. Subcommands:
- **`run`** — batch mode: reads a file/stdin, processes through the pipeline, writes NDJSON. Supports `--parquet`, `--opensearch`, `--splunk-hec`, `--dead-letter` sinks.
- **`serve`** — starts the operator console HTTP server on port 8787.
- **`raw get <locator>`** — retrieves original bytes from vault.
- **`pack test`** — runs fixtures for all packs.
- **`pack list`** — lists installed packs.
- **`verify`** — verifies integrity chain from an NDJSON file.
- **`generate`** — drafts candidate packs from a dead-letter file (CLI-based).

### [pipeline.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/pipeline.rs) — 233 lines
Wires vault, pack library, and attestor into a single `process()` call per event. Tracks `Stats` (received, parsed, unidentified, by_pack). Produces `Processed` containing the OCSF event, disposition, and raw ref.

### [server.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/server.rs) — 464 lines
Axum HTTP server. Endpoints: `/api/stats`, `/api/packs`, `/api/events`, `/api/ingest`, `/api/raw/{locator}`, `/api/verify`, `/api/tamper`, `/api/clear`, `/api/clusters`, `/api/generate`. The UI is embedded via `include_str!`.

### [sinks.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/sinks.rs) — 736 lines
**`SinkSet`** with three optional sinks:
- **`ParquetSink`** — writes 4-column Parquet files (uid, class_uid, time, event_json) using raw `parquet` crate.
- **`OpenSearchSink`** — bulk HTTP/1.1 posts to `/_bulk` endpoint using raw TCP sockets (no reqwest dependency!).
- **`SplunkHecSink`** — HTTP posts to `/services/collector/event` with token auth.
All sinks use bounded batching.

### [generator.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/generator.rs) — 389 lines
CLI-based dead-letter clustering and candidate pack drafting. Reads NDJSON dead-letter files, clusters by first-token shape, drafts candidate YAML packs. Optional LLM sidecar refinement over stdin/stdout JSON protocol.

### [integrity_state.rs](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/integrity_state.rs) — ~190 lines
Persists Ed25519 signing keys and checkpoints to disk for chain resumption across restarts.

### [ui/index.html](file:///C:/Users/jampa/Documents/PROJECTS/ULPF/crates/ulpf-cli/src/ui/index.html) — 117 lines (~32 KB)
The entire operator console UI: HTML + CSS + JavaScript in a single file. Dark theme, grid layout, live metrics, event table with drawer inspector, raw proof retrieval, tamper-and-verify demo, pack browser, AI generator panel with cluster viewer.

---

## Supporting Directories

| Directory | Contents |
|---|---|
| `testdata/` | `mixed.log` — 1 KB sample file with mixed log lines |
| `tools/` | `gen_bench.py` — Python script for generating benchmark data |
| `scripts/` | `setup.sh`/`.ps1` — environment setup, `prepare-real-dataset.sh`/`.ps1` — dataset preparation |
| `docs/` | `ARCHITECTURE.md`, `DATASETS.md`, `PACK_GENERATOR.md`, `ROADMAP.md`, `SINKS.md`, `TESTING.md` |
| `schema/` | Vendored OCSF 1.9.0 JSON schema files |
| `data/` | Runtime data: vault segments, integrity keys/checkpoints |
| `.github/` | CI workflows |
