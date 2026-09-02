#!/usr/bin/env sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required. Install it from https://rustup.rs and rerun this script." >&2
  exit 1
fi

rustup toolchain install stable --profile minimal --component rustfmt --component clippy
cargo build --locked --release
cargo test --workspace --locked
cargo run --locked --quiet -- test --packs packs

printf '%s\n' "ULPF is ready: ./target/release/ulpf"
printf '%s\n' "Start the console: ./target/release/ulpf serve"
