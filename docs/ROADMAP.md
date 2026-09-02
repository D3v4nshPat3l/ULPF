# SIH 2026 roadmap

## Implemented prototype

- Byte-exact zstd raw vault with CRC verification and indexed retrieval.
- OCSF 1.9.0 normalization with RFC 8785 canonicalization.
- Persistent SHA-256/BLAKE3 hash chains and Ed25519 checkpoints.
- File, stdin, HTTP-console, and UDP syslog ingestion.
- Five Source Packs and seven built-in decoders.
- Bounded, air-gap-compatible operator console.
- NDJSON, dead-letter, Parquet, OpenSearch Bulk, and Splunk HEC output.
- Container and CI scaffolding.

## Next milestone: production core

- Generate validators from the vendored OCSF schema and validate class-specific attributes in CI.
- TCP/TLS syslog with octet-counted and delimiter framing.
- Atomic checkpoint replacement and configurable checkpoint intervals.
- Pack hot reload with pre-activation fixture gates.
- Add Cisco ASA, Check Point, WAF, proxy, VPN, router, NAC, and mail-gateway packs using real corpora.
- CLI integration tests, parser fuzzing, and cross-platform build matrix.

## Differentiators

- Template clustering over the dead-letter stream.
- Offline, human-reviewed Source Pack drafting assistant with provenance and
  fixture gates.
- Iceberg and Kafka sinks, plus TLS-native remote transport.
- Stable derived features for downstream anomaly detection.

## Finale proof

- Repeatable benchmark on declared hardware.
- Air-gapped build artifact or vendored Cargo dependency bundle.
- Software bill of materials, signed release checksum, and container scan.
- Two-minute demo video, two-page architecture brief, and presentation deck.

The presentation is intentionally excluded from this repository milestone, per the team’s current plan.
