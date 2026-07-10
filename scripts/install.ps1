Param(
    [switch]$SkipVenv
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not $SkipVenv) {
    if (-not (Test-Path .venv)) { python -m venv .venv }
    .\.venv\Scripts\pip install -r requirements-dev.txt
}

Write-Host "Basilisk install complete"
