# Testing and verification

## Required pull-request checks

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run --locked --quiet -- test --packs packs
cargo build --release --locked
```

The Rust suite currently contains 183 `#[test]` cases plus one compiled documentation test, for 184 executed tests. Source Pack fixtures add 13 end-to-end normalization cases with field assertions.

## End-to-end integrity test

```bash
./target/release/ulpf run \
  --packs packs \
  --vault data/check/vault \
  --integrity-dir data/check/integrity \
  --chain check \
  --input testdata/mixed.log \
  --output data/check/events.ndjson \
  --dead-letter data/check/dead-letter.ndjson

./target/release/ulpf verify data/check/events.ndjson \
  --checkpoint data/check/integrity/check.checkpoint.json \
  --public-key data/check/integrity/ed25519-signing.pub
```

Expected: five events received, four parsed, one unidentified and preserved, followed by signed-checkpoint and trusted-key verification.

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
