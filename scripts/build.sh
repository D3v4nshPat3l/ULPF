#!/usr/bin/env bash
set -e

echo "Building ULPF workspace..."
cargo build --release

echo "Checking formatting..."
cargo fmt -- --check

echo "Running tests..."
cargo test --workspace

echo "Build and tests complete!"
