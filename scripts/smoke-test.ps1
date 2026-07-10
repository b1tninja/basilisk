Param(
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing | Out-Null
Invoke-WebRequest -Uri "$BaseUrl/pks/lookup?op=stats" -UseBasicParsing | Out-Null
Write-Host "Smoke test OK: $BaseUrl"
