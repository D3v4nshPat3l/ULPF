#!/usr/bin/env bash
#
# Run the same gate CI runs, locally, in the same order.
#
# The point is that a green run here means a green run there. The previous
# version of this script ran build, fmt and test only, so it could pass while
# CI failed on clippy or on the pack enum audit — which is worse than having no
# script, because it is trusted.
#
# CI additionally vendors dependencies and passes --offline to prove the
# air-gapped build. That is left to CI: doing it here would rewrite the
# developer's .cargo/config.toml.
set -euo pipefail

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "Build (release, locked)"
cargo build --release --locked

step "Tests"
cargo test --workspace --locked

step "Source-pack fixtures"
cargo run --release --locked --quiet -- test --packs packs

step "Pack enum audit against the vendored OCSF schema"
if command -v python3 >/dev/null 2>&1; then
  python3 tools/audit_pack_enums.py
elif command -v python >/dev/null 2>&1; then
  python tools/audit_pack_enums.py
else
  echo "python not found — skipping the enum audit, which CI will still run" >&2
  exit 1
fi

step "Formatting"
cargo fmt --all -- --check

step "Clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

printf '\n\033[1;32mAll gates passed.\033[0m\n'
printf 'Coverage against the real corpora is not run here: it needs ~150 MB of\n'
printf 'public capture data. See docs/DATASETS.md, then:\n'
printf '  python tools/measure_coverage.py --check\n'
