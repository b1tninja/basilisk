Param()

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Copy-Item .env.test.example .env.test -Force
Copy-Item .env.example .env -Force

function Set-EnvVar {
    param([string]$File, [string]$Key, [string]$Value)
    $lines = Get-Content $File
    $found = $false
    $lines = $lines | ForEach-Object {
        if ($_ -match "^$([regex]::Escape($Key))=") {
            $found = $true
            "$Key=$Value"
        } else {
            $_
        }
    }
    if (-not $found) {
        $lines += "$Key=$Value"
    }
    $lines | Set-Content $File
}

if ($env:BASILISK_TOKEN_SECRET) {
    Set-EnvVar .env.test "BASILISK_TOKEN_SECRET" $env:BASILISK_TOKEN_SECRET
    Set-EnvVar .env "BASILISK_TOKEN_SECRET" $env:BASILISK_TOKEN_SECRET
}

Write-Host "Prepared .env.test and .env for CI"
