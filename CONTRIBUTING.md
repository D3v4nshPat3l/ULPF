# Contributing to ULPF

ULPF is a team project for Smart India Hackathon 2026. Keep changes reviewable, evidence-backed, and aligned with PS 26156.

## Local setup

Run `scripts/setup.ps1` on Windows or `scripts/setup.sh` on Linux/macOS. Work from a short-lived branch created from `main`:

```bash
git switch main
git pull --ff-only
git switch -c feat/short-description
```

Use `fix/`, `feat/`, `docs/`, `test/`, or `chore/` prefixes. Do not commit `data/`, real datasets, generated benchmark logs, signing keys, vault segments, IDE settings, or build output.

## Pull requests

A pull request must explain the problem, the implementation, verification commands, and risk. Keep one concern per pull request. Require another team member to review integrity, vault-format, decoder, or Source Pack changes.

Before pushing:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run --locked --quiet -- test --packs packs
```

## Source Pack changes

- Use a stable lowercase identifier.
- Use narrow detectors; generic fallbacks receive lower precedence.
- Do not map a field unless the OCSF semantic and type are known.
- Retain source alternatives that were not used in `unmapped`.
- Add authentic, redacted fixtures for every observed shape.
- Document dataset provenance without committing restricted/raw corpora.
- Ensure all pack fixtures pass before requesting review.

## Commit messages

Use an imperative conventional prefix, for example:

```text
fix(vault): verify block CRC during retrieval
feat(receiver): add UDP syslog ingestion
docs(dataset): record real-corpus benchmark protocol
```

Avoid commits named `update`, `changes`, or `final` because they make forensic review and bisecting needlessly difficult.
