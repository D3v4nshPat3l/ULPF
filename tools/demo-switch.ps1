<#
.SYNOPSIS
  One-command switch between "raw traffic into Wazuh" and "same traffic
  through ULPF" for the live demo, on Machine A.

.WHY THIS IS A SCRIPT, NOT A WEB PAGE
  A browser page calling these APIs from any other origin (a local HTML
  file, a second localhost port, anything) gets refused outright -- the
  console's own CSRF guard (same_origin_only in server.rs) rejects any
  request whose Origin header doesn't exactly match the simulator's own
  bound address, which is exactly the kind of cross-origin call a "one
  click" HTML control page would have to make. A script using
  Invoke-RestMethod never sends an Origin header at all (only browsers
  add one for cross-origin fetches), so it passes the same guard cleanly
  as long as it talks to the exact host:port each simulator is bound to.

.WHEN YOU NEED THIS AT ALL
  Usually you do not. The single-laptop demonstration in docs/DEMO.md flips
  the target with the Wazuh/ULPF switch on the simulator page itself, which
  is same-origin and needs no script. This exists for the variant where two
  simulator instances run at once -- one aimed at the SIEM, one at ULPF --
  so both can be driven from outside the browser.

.SETUP (once)
  Fill in the four values below after starting both simulator instances.
  Both tokens are printed at each instance's startup.

.USAGE
  .\demo-switch.ps1 -ToUlpf     # same as double-clicking switch-to-ulpf.bat
  .\demo-switch.ps1 -ToWazuh    # same as double-clicking switch-to-wazuh.bat
#>

param(
    [switch]$ToUlpf,
    [switch]$ToWazuh
)

# ---- defaults; real values belong in demo-switch.local.ps1, not here ----
$WazuhSimUrl   = "http://127.0.0.1:8788"
$WazuhSimToken = "PASTE_WAZUH_SIM_TOKEN_HERE"
$UlpfSimUrl    = "http://127.0.0.1:8789"
$UlpfSimToken  = "PASTE_ULPF_SIM_TOKEN_HERE"
$SourceIds     = @("iptables", "snort", "apache")
$Eps           = 500

# demo-switch.local.ps1 sits next to this file, is gitignored, and is where
# the real tokens go - never edit the placeholders above in place. Create
# it once with the same variable assignments, real values this time:
#   $WazuhSimToken = "the real token"
#   $UlpfSimToken  = "the real token"
# A console token committed to a public repo is a real credential leak,
# not just messy git history.
$localOverride = Join-Path $PSScriptRoot "demo-switch.local.ps1"
if (Test-Path $localOverride) {
    . $localOverride
    Write-Host "Loaded local overrides from demo-switch.local.ps1"
} else {
    Write-Host "No demo-switch.local.ps1 found next to this script - using the placeholders above." -ForegroundColor Yellow
    Write-Host "Create that file with real tokens before this will work. See the comment at the top of this script." -ForegroundColor Yellow
}
# ----------------------------------------------

function Stop-AllSources {
    param($BaseUrl, $Token)
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/sim/stop-all" `
        -Headers @{ Authorization = "Bearer $Token" } | Out-Null
}

function Start-Sources {
    param($BaseUrl, $Token, $Ids, $Rate)
    foreach ($id in $Ids) {
        $body = @{ id = $id; on = $true; eps = $Rate } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/sim/toggle" `
            -Headers @{ Authorization = "Bearer $Token" } `
            -ContentType "application/json" -Body $body | Out-Null
        Write-Host "  started $id at $Rate eps on $BaseUrl"
    }
}

if (-not $ToUlpf -and -not $ToWazuh) {
    Write-Host "Pass -ToUlpf or -ToWazuh. Example: .\demo-switch.ps1 -ToUlpf"
    exit 1
}

try {
    if ($ToUlpf) {
        Write-Host "Stopping Wazuh-direct sources..."
        Stop-AllSources -BaseUrl $WazuhSimUrl -Token $WazuhSimToken
        Write-Host "Starting the same sources into ULPF..."
        Start-Sources -BaseUrl $UlpfSimUrl -Token $UlpfSimToken -Ids $SourceIds -Rate $Eps
        Write-Host "Done. Traffic now flows through ULPF." -ForegroundColor Green
    } else {
        Write-Host "Stopping ULPF-target sources..."
        Stop-AllSources -BaseUrl $UlpfSimUrl -Token $UlpfSimToken
        Write-Host "Starting the same sources back into Wazuh..."
        Start-Sources -BaseUrl $WazuhSimUrl -Token $WazuhSimToken -Ids $SourceIds -Rate $Eps
        Write-Host "Done. Traffic back to Wazuh directly." -ForegroundColor Green
    }
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Common causes: a token wasn't filled in, one of the two simulator instances isn't running, or a source id is misspelled." -ForegroundColor Red
    exit 1
}
