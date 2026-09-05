# Changelog

Notable changes, newest first. Semantic Versioning applies from the first
tagged release; until then everything lives under Unreleased.

Figures quoted here are reproducible from the repository — see
[docs/DATASETS.md](docs/DATASETS.md) for coverage and
[docs/THROUGHPUT.md](docs/THROUGHPUT.md) for ingest rate.

## [Unreleased]

### Ingest and preservation

- Append-only zstd raw vault: byte-exact, CRC-verified, indexed retrieval by
  locator. The vault append happens **before** parsing, so a record ULPF cannot
  interpret is still preserved and still addressable.
- File, stdin and UDP syslog ingestion. The receiver enlarges its socket buffer
  at bind; the OS default drops 37% of datagrams at 15,000 events/sec.

### Normalization

- OCSF 1.9.0 output, schema vendored at `schema/ocsf` as an unmodified upstream
  snapshot.
- Ten decoders: RFC 3164 and RFC 5424 syslog, CEF, LEEF, JSON, XML, CSV,
  key-value, and regex.
- Eighteen declarative Source Packs, 37 fixtures, 100% field accuracy.
- 99.8256% coverage over 305,582 records of public capture data, with the 533
  misses enumerated rather than rounded away.

### Integrity

- Per-event content fingerprint over RFC 8785 canonical JSON, chained to its
  predecessor, with Ed25519-signed checkpoints.
- RFC 6962 Merkle log over event fingerprints, signed into every checkpoint.
- `ulpf prove` / `ulpf verify-proof`: prove one record belongs to the log in
  `O(log n)` hashes, verifiable by someone holding no other part of it.
- `ulpf consistency`: bridge a proof issued against an older tree to the
  current signed root, which is what shows the log was extended and not
  rewritten.

### Output

- NDJSON by default; dead-letter stream for unparsed records.
- Parquet archive of whole OCSF documents, OpenSearch Bulk and Splunk HEC
  fan-out, all batched.
- Columnar feature table with a fixed, versioned 24-column contract for model
  training, distinct from the document archive.

### Operations

- Embedded operator console, compiled into the binary: no CDN, no web font, no
  telemetry, no network call on any path.
- Pack drafting from unparsed traffic — a deterministic generator, and an
  optional local model — with fixture gates before activation.
- Two-stage container onto distroless with a read-only root filesystem and all
  capabilities dropped.
- Graceful shutdown on Ctrl-C and SIGTERM: signs a final checkpoint and closes
  the Parquet writers, without which the feature table is never readable.

### Correctness fixes worth naming

These shipped broken and were found by running the system rather than by
testing it, which is why they are listed:

- Apache and Squid numbered HTTP methods in the order they were written down
  rather than the order OCSF defines, recording every `GET` as `Connect` and
  every `POST` as `Delete`. Both packs passed every fixture for weeks.
  `tools/audit_pack_enums.py` now checks every pack against the vendored schema
  in CI.
- A non-ASCII byte inside an XML element killed the collector — a slice on a
  character boundary. Now a byte comparison, with a hostile-input test suite.
- `/api/approve` joined an operator-supplied pack id onto a path, and
  `Path::join` discards the base entirely when handed an absolute path, so a
  pack could be written anywhere on the filesystem.
- The console reported a healthy chain as broken about forty seconds into any
  demonstration, when the 501st event evicted the record its successor pointed
  at.
- Parquet partitioning wrote every row to `dt=1970-01-01` — nanoseconds read as
  milliseconds.
