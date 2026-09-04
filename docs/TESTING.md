# Testing and verification

## Required pull-request checks

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run --locked --quiet -- test --packs packs
cargo build --release --locked
```

The Rust suite currently contains 188 `#[test]` cases plus one compiled documentation test, for 189 executed tests. Source Pack fixtures add 13 end-to-end normalization cases with field assertions.

## End-to-end integrity and sink test

```bash
./target/release/ulpf run \
  --packs packs \
  --vault data/check/vault \
  --integrity-dir data/check/integrity \
  --chain check \
  --input testdata/mixed.log \
  --output data/check/events.ndjson \
  --dead-letter data/check/dead-letter.ndjson \
  --parquet data/check/events.parquet

./target/release/ulpf verify data/check/events.ndjson \
  --checkpoint data/check/integrity/check.checkpoint.json \
  --public-key data/check/integrity/ed25519-signing.pub
```

Expected: five events received, four parsed, one unidentified and preserved, followed by signed-checkpoint and trusted-key verification.

Validate the Parquet footer and columns with an installed reader:

```bash
python -c "import pyarrow.parquet as pq; t=pq.read_table('data/check/events.parquet'); assert t.num_rows == 5; assert t.column_names == ['event_json', 'class_uid', 'activity_id', 'time']; print(t.schema)"
```

Then draft a candidate from the one unknown record:

```bash
./target/release/ulpf draft \
  --dead-letter data/check/dead-letter.ndjson \
  --output data/check/candidates
```

The command must report one candidate and write `manifest.json` with
`approval_required: true`. Candidate YAML is tested through the same compiler;
it is not added to `packs/` automatically.

## Losslessness checks

- Input is read as bytes with record terminators preserved.
- Invalid UTF-8 enters the vault unchanged; dead letters include hex when text is lossy.
- Blank records are not silently skipped.
- Input/output/dead-letter path collisions are rejected before output creation.
- Every emitted locator references a flushed vault block.
- Vault decompression validates the block header, size, and CRC-32.
- `ulpf raw` emits only stored bytes and does not append a newline.

## Browser acceptance checks

1. Start `ulpf serve`.
2. Select a real `.log` file.
3. Process records and confirm counters, coverage, and pack distribution.
4. Select an event; inspect normalized and extracted views.
5. Retrieve Raw proof and compare its hash with `raw_data_hash.value`.
6. Verify integrity.
7. Tamper with the in-memory copy and confirm fingerprint verification fails.
8. Clear the view and confirm counters/vault state are retained.

The screenshots under `docs/images` were generated from this flow, not mocked.

## Two gates that fixture scoring cannot provide

Every pack passes its own fixtures. That is necessary and not sufficient, and
two checks exist because of specific failures that slipped past it.

### Enum audit — `tools/audit_pack_enums.py`

A pack maps a vendor's vocabulary onto OCSF enum values by hand. Get a number
wrong and the pack still compiles, the fixture still passes (it asserts
whatever the pack produces), and the event is still schema-shaped. It is only
wrong in *meaning*.

That is not hypothetical. The Apache and Squid packs both numbered HTTP methods
in the order someone wrote them down rather than the order OCSF defines, so
every `GET` was recorded as `Connect` and every `POST` as `Delete`. A query for
GETs matched nothing; a query for DELETEs matched every POST. Both packs passed
every check in the repository for weeks.

The audit reads the vendored schema and fails when a name maps to an id whose
caption is a different name. It needs no network, so it runs in the air-gapped
CI job.

```bash
python tools/audit_pack_enums.py
```

### Coverage regression — `tools/measure_coverage.py --check`

A pack can pass its fixtures and still stop claiming most of the traffic it
used to: a detector tightened by one character keeps the fixture working and
drops 30% of production records. `tools/coverage_baseline.json` records what
each corpus achieves today, and `--check` fails when any of them, or the total,
falls below it.

```bash
python tools/measure_coverage.py --check
python tools/measure_coverage.py --write-baseline   # after an intended change
```

A run with any corpus absent is refused rather than passed: a missing corpus is
exactly how a broken pack would hide from the check meant to catch it.

This one runs in a **separate** workflow, not the air-gapped job. It needs
~150 MB from the Honeynet Project and Loghub, and putting a download inside the
job whose purpose is proving offline operation would make that proof
meaningless. It runs weekly, on demand, and on pushes that touch packs or the
decode/pack crates.
