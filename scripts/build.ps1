# Run the same gate CI runs, locally, in the same order.
#
# The point is that a green run here means a green run there. The previous
# version ran build, fmt and test only, so it could pass while CI failed on
# clippy or on the pack enum audit -- which is worse than having no script,
# because it is trusted.
#
# CI additionally vendors dependencies and passes --offline to prove the
# air-gapped build. That is left to CI: doing it here would rewrite the
# developer's .cargo/config.toml.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Step($name) {
    Write-Host ''
    Write-Host "==> $name" -ForegroundColor Cyan
}

# A native command failing does not throw, so every step is checked explicitly.
function Invoke-Step($name, [scriptblock]$body) {
    Step $name
    & $body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step 'Build (release, locked)' { cargo build --release --locked }
Invoke-Step 'Tests'                   { cargo test --workspace --locked }
Invoke-Step 'Source-pack fixtures'    { cargo run --release --locked --quiet -- test --packs packs }

$python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue) }
if (-not $python) {
    Write-Host 'python not found -- the enum audit cannot run, and CI will still run it' -ForegroundColor Red
    exit 1
}
Invoke-Step 'Pack enum audit against the vendored OCSF schema' {
    & $python.Source tools/audit_pack_enums.py
}

Invoke-Step 'Formatting' { cargo fmt --all -- --check }
Invoke-Step 'Clippy'     { cargo clippy --workspace --all-targets --locked -- -D warnings }

Write-Host ''
Write-Host 'All gates passed.' -ForegroundColor Green
Write-Host 'Coverage against the real corpora is not run here: it needs ~150 MB of'
Write-Host 'public capture data. See docs/DATASETS.md, then:'
Write-Host '  python tools/measure_coverage.py --check'
