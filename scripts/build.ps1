$ErrorActionPreference = "Stop"

Write-Host "Building ULPF workspace..."
cargo build --release

Write-Host "Checking formatting..."
cargo fmt -- --check

Write-Host "Running tests..."
cargo test --workspace

Write-Host "Build and tests complete!"
