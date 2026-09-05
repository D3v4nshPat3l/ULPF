# ULPF architecture

## Scope

ULPF is the normalization layer between perimeter-device telemetry and security analytics systems. It receives opaque records, preserves them before interpretation, extracts source-specific fields, emits OCSF 1.9.0 JSON, and binds every normalized event to the original bytes through an integrity chain.

It is deliberately not a SIEM. Correlation, alert triage, visualization, and machine learning consume ULPF output downstream.

## Processing path

```text
receiver -> raw vault -> source identification -> decoder chain -> OCSF mapping -> attestation -> fan-out sinks
                |                |                                      |
                |                +-> no match/failure -> dead letter ---+
                +-> constant-time retrieval by raw locator
```

The ordering is a correctness property. The vault append precedes parsing, and a batch is flushed before any normalized row containing its locator is published. An unknown or malformed event is still vaulted, hashed, attested, emitted as a minimal OCSF event, and copied to the dead-letter stream.

## Components

| Crate | Responsibility |
|---|---|
| `ulpf-core` | Receipt envelope, transport, borrowed field map, raw locator, disposition |
| `ulpf-decode` | Ten decoders: RFC 3164/5424 syslog, CEF, LEEF, JSON, XML, CSV, key-value, regex |
| `ulpf-pack` | Declarative Source Pack schema, validation, compilation, fixtures, scoring |
| `ulpf-ocsf` | OCSF event construction, RFC 8785 canonicalization, hash chain, checkpoints, RFC 6962 Merkle log |
| `ulpf-vault` | Append-only block-compressed byte archive and indexed retrieval |
| `ulpf-cli` | File/stdin/UDP ingestion, NDJSON and data-lake/SIEM sinks, pack drafting, verification, embedded operator console |

## Raw vault

Each record is stored as a length-prefixed byte sequence. Records are grouped into zstd-compressed blocks and rotated into segments. Each block includes uncompressed coordinates, compressed and uncompressed lengths, and CRC-32. The reader verifies the authoritative block header, decompressed length, and CRC before returning a record.

`RawRef(segment, offset, len)` serializes as `ulpf:raw:<segment>:<offset>:<length>` and is placed at `unmapped.ulpf_raw_locator`. The receipt envelope is retained at `unmapped.ulpf_receipt`. `metadata.original_event_uid` remains available for a source-native identifier.

## Integrity model

Each event carries the OCSF `record_integrity` profile. Its fingerprint covers canonical event content plus the previous-event link, excluding only its own fingerprint/signature fields. ULPF uses SHA-256 by default and supports BLAKE3 with the OCSF `Other` algorithm identifier.

The Ed25519 private key is generated once inside the configured integrity directory. The latest signed checkpoint and public key are persisted separately. A process restart verifies the stored checkpoint and resumes from its exact event UID, type UID, sequence, and fingerprint. Independent verification can require both the checkpoint and an out-of-band public key.

This provides tamper evidence plus a trusted anchor. A hash chain alone cannot authenticate a completely replaced stream.

Alongside the chain, every checkpoint signs a Merkle tree head over the event fingerprints, built to RFC 6962 with its `0x00`/`0x01` leaf and node domain separation. The chain gives cheap sequential tamper-evidence at write time; the tree gives cheap selective proof at read time. Neither replaces the other. Leaf hashes are persisted next to the checkpoint and reloaded on restart only up to the size the last signed checkpoint commits to, so the tree never extends past what a key has attested to.

The tree is what makes a single record shareable. Proving one event by replaying the chain means disclosing every other event; an inclusion proof does it in `ceil(log2 n)` hashes, verified against the signed root by a party that holds no other part of the log. Because a proof reproduces only the root it was issued under, consistency proofs (RFC 6962 section 2.1.3) bridge an older tree size to the current signed root, and fail by construction if the log was rewritten rather than merely extended.

## Source Packs

A Source Pack is YAML with identity detectors, a decoder chain, OCSF mappings, enum translations, provenance, and golden fixtures. Packs are compiled once at load. A filesystem watcher recompiles the library
when a file in the packs directory changes, so a new source is onboarded by
dropping in a YAML file — no restart. A pack that fails to compile is logged
and skipped; the previously loaded library stays in service. Unknown fields, empty detectors, missing base mappings, invalid enum references, unsafe framework-owned paths, invalid ranges, and malformed mapping objects fail during load.

The hot path is deterministic: no network or model call executes per event. The
offline `ulpf draft` assistant clusters dead letters and drafts YAML candidates;
strict compilation, fixtures, and human approval remain mandatory before a pack
can enter the runtime library.

## Runtime interfaces

- `ulpf run`: file or stdin to NDJSON, raw vault, checkpoint, optional dead-letter output, and bounded Parquet/OpenSearch/Splunk fan-out.
- `ulpf draft`: dead-letter clustering and fixture-tested candidate Source Packs.
- `ulpf listen`: UDP syslog receiver on an operator-selected socket.
- `ulpf replay`: replay a capture over UDP at a fixed rate, for load testing.
- `ulpf decoders`: list the built-in decoders a pack may name.
- `ulpf serve`: local REST API, operator console and traffic simulator, with no
  CDN or external runtime dependency. Binds a UDP syslog receiver on
  `--syslog-bind`, which is configurable so two collectors can share a host.
- `ulpf raw`: exact byte retrieval by locator.
- `ulpf verify`: event-chain verification with optional checkpoint and trusted public key.
- `ulpf prove`: inclusion proof for one event against the chain's signed Merkle root.
- `ulpf consistency`: proof that an earlier tree size is an unmodified prefix of the current one.
- `ulpf verify-proof`: checks a proof against a checkpoint and a trusted key, reading no other part of the log.
- `ulpf test`: Source Pack fixture quality gate.

## Security boundaries

The console binds to loopback by default. It has no authentication and must not be exposed directly to an untrusted network. The Docker Compose file publishes it only on `127.0.0.1`, drops Linux capabilities, uses a read-only root filesystem, and persists only `/app/data`.

The server bounds JSON bodies to 4 MiB, accepts at most 2,000 non-empty records per request, and keeps at most 500 recent events in memory. Evicting or clearing rows advances a retained verification anchor instead of silently making the remaining window look like genesis.

## Current limitations

- UDP syslog is implemented; TCP/TLS and Kafka remain roadmap work.
- Parquet, OpenSearch Bulk, and Splunk HEC adapters use plain HTTP to a trusted
  local endpoint. TLS termination and destination-specific authentication are
  deployment responsibilities.
- The event model enforces OCSF base fields and pack guardrails but is not yet validated against a generated full-class JSON Schema in CI.
- The console uses a synchronous critical section for the single-writer pipeline. This preserves chain order but requires sharded collectors for horizontal throughput.
