## What changed

Describe the user-visible and technical change.

## Why

Link the issue or explain the failure/requirement addressed.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo run --locked --quiet -- test --packs packs`
- [ ] `cargo build --release --locked`
- [ ] Real-data evidence is attached when parser or coverage behavior changes
- [ ] Screenshots are attached when operator-visible UI changes
- [ ] Documentation and changelog are updated where needed

## Security and losslessness

Explain any effect on raw-byte preservation, integrity, trust boundaries,
network exposure, or sensitive data handling. Write `None` when not applicable.

