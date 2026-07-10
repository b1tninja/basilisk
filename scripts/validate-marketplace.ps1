Param(
    [string]$TemplatePath = "marketplace/package"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path $TemplatePath)) {
    & "$PSScriptRoot/package-marketplace.ps1"
}
if (Get-Module -ListAvailable -Name arm-ttk) {
    Test-AzMarketplacePackage -TemplatePath $TemplatePath
} else {
    Write-Warning "arm-ttk not installed; running az deployment validate instead"
    az deployment group validate -g basilisk-sandbox -f "$TemplatePath/mainTemplate.json" -p "@$TemplatePath/test-params.json"
}
