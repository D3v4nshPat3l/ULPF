[CmdletBinding()]
param(
    [string]$DatasetRoot = "../realdata",
    [string]$Output = "testdata/real/all-perimeter.log"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$sources = @(
    (Join-Path $DatasetRoot "SotM30-anton.log"),
    (Join-Path $DatasetRoot "SotM34/iptables/iptablesyslog"),
    (Join-Path $DatasetRoot "SotM34/snort/snortsyslog")
)
foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing real dataset file: $source. See docs/DATASETS.md."
    }
}

$parent = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$destination = [System.IO.File]::Open($Output, [System.IO.FileMode]::Create)
try {
    foreach ($source in $sources) {
        $inputStream = [System.IO.File]::OpenRead($source)
        try { $inputStream.CopyTo($destination) } finally { $inputStream.Dispose() }
    }
} finally {
    $destination.Dispose()
}

$lineCount = 0
$reader = [System.IO.File]::OpenText($Output)
try { while ($null -ne $reader.ReadLine()) { $lineCount++ } } finally { $reader.Dispose() }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash.ToLowerInvariant()
Write-Host "Prepared $Output"
Write-Host "Records: $lineCount"
Write-Host "SHA-256: $hash"
