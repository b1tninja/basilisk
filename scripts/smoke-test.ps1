Param(
    [string]$BaseUrl = "http://localhost:8080",
    # Timeout per request in seconds.  Long enough for a cold Azure Function
    # start (Flex Consumption can take 20-30 s) but short enough to fail
    # CI promptly when the service is genuinely down.
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = "Stop"
$fail = $false

function Check-Status {
    param([string]$Label, [string]$Url)
    Write-Host -NoNewline ("  {0,-50}" -f $Label)
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing `
                    -TimeoutSec $TimeoutSec -MaximumRedirection 5
        Write-Host "HTTP $($resp.StatusCode) OK"
    } catch {
        Write-Host "FAIL: $_"
        $script:fail = $true
    }
}

function Check-Body {
    param([string]$Label, [string]$Url, [string]$Pattern)
    Write-Host -NoNewline ("  {0,-50}" -f $Label)
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing `
                    -TimeoutSec $TimeoutSec -MaximumRedirection 5
        if ($resp.Content -match [regex]::Escape($Pattern)) {
            Write-Host "OK (found '$Pattern')"
        } else {
            Write-Host "FAIL (pattern not found in response)"
            $script:fail = $true
        }
    } catch {
        Write-Host "FAIL: $_"
        $script:fail = $true
    }
}

Write-Host "Smoke testing $BaseUrl ..."
Write-Host ""

# 1. Health endpoint
Check-Status "/health"                       "$BaseUrl/health"

# 2. HKP stats — full table scan can be slow; TimeoutSec covers it
Check-Status "/pks/lookup?op=stats"          "$BaseUrl/pks/lookup?op=stats"

# 3. Static homepage — match HTML title, not JS bundle content
Check-Body   "/ (HTML title check)"          "$BaseUrl/"  "Basilisk"

# 4. Search API — confirms the route is live
Check-Status "/api/v1/search?q=test"         "$BaseUrl/api/v1/search?q=test%40example.com"

Write-Host ""
if ($fail) {
    Write-Host "Smoke test FAILED: $BaseUrl"
    exit 1
} else {
    Write-Host "Smoke test OK: $BaseUrl"
}
