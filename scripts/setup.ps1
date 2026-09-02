[CmdletBinding()]
param([switch]$SkipTests)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw "rustup is required. Install it from https://rustup.rs, reopen PowerShell, and rerun this script."
}

rustup toolchain install stable --profile minimal --component rustfmt --component clippy
cargo build --locked --release
if (-not $SkipTests) {
    cargo test --workspace --locked
    cargo run --locked --quiet -- test --packs packs
}

Write-Host "ULPF is ready: .\target\release\ulpf.exe" -ForegroundColor Green
Write-Host "Start the console: .\target\release\ulpf.exe serve" -ForegroundColor Green
