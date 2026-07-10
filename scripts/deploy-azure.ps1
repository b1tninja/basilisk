<#
.SYNOPSIS
  Deploy Basilisk Azure infrastructure (Bicep subscription deployment).

.DESCRIPTION
  Reads tenant and subscription from the active `az login` session.
  No manual editing of main.bicepparam is required.

.EXAMPLE
  az login
  .\scripts\deploy-azure.ps1

.EXAMPLE
  .\scripts\deploy-azure.ps1 -NamePrefix basilisk-prod -Location westus2 -MailProvider gmail
#>
[CmdletBinding()]
param(
    [string]$NamePrefix = "basilisk-dev",
    [string]$Location = "",
    [ValidateSet("office365", "gmail")]
    [string]$MailProvider = "office365",
    [switch]$RequireManagerApproval,
    [string]$SubscriptionId = "",
    [string]$ParamFile = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Assert-AzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw @"
Azure CLI ('az') not found. Install it, then open a new terminal:
  winget install -e --id Microsoft.AzureCLI
"@
    }
}

function Get-AzAccountContext {
    $accountJson = az account show 2>$null
    if (-not $accountJson) {
        throw "Not logged in to Azure. Run: az login"
    }
    return $accountJson | ConvertFrom-Json
}

function Resolve-DeployLocation {
    param(
        [string]$NamePrefix,
        [string]$RequestedLocation
    )

    if ($RequestedLocation) {
        return $RequestedLocation
    }

    $rgName = "${NamePrefix}-rg"
    $existingRgLocation = az group show --name $rgName --query location -o tsv 2>$null
    if ($existingRgLocation) {
        Write-Host "Using location from existing resource group: $rgName -> $existingRgLocation"
        return $existingRgLocation.Trim()
    }

    $configuredLocation = az config get defaults.location -o tsv 2>$null
    if ($configuredLocation) {
        Write-Host "Using az config defaults.location: $configuredLocation"
        return $configuredLocation.Trim()
    }

    Write-Host "No location specified; falling back to eastus (override with -Location)"
    return "eastus"
}

Assert-AzCli
$account = Get-AzAccountContext

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId | Out-Null
    $account = Get-AzAccountContext
}

$tenantId = $account.tenantId
$subscriptionName = $account.name
$subscriptionId = $account.id
$Location = Resolve-DeployLocation -NamePrefix $NamePrefix -RequestedLocation $Location

Write-Host "Subscription: $subscriptionName ($subscriptionId)"
Write-Host "Tenant:       $tenantId"
Write-Host "Deploying:    $NamePrefix -> ${NamePrefix}-rg ($Location)"

$deploymentName = "basilisk-$(Get-Date -Format 'yyyyMMddHHmmss')"

$deployArgs = @(
    "deployment", "sub", "create",
    "--name", $deploymentName,
    "--location", $Location,
    "--template-file", "infra/main.bicep"
)

if ($ParamFile) {
    if (-not (Test-Path $ParamFile)) {
        throw "Parameter file not found: $ParamFile"
    }
    $deployArgs += @("--parameters", $ParamFile)
} else {
    $deployArgs += @(
        "--parameters",
        "namePrefix=$NamePrefix",
        "location=$Location",
        "entraTenantId=$tenantId",
        "mailProvider=$MailProvider",
        "requireManagerApproval=$($RequireManagerApproval.IsPresent.ToString().ToLower())"
    )
}

az @deployArgs

$outputs = az deployment sub show `
    --name $deploymentName `
    --query "properties.outputs" -o json | ConvertFrom-Json

Write-Host ""
Write-Host "Deployment complete: $deploymentName" -ForegroundColor Green
Write-Host "  Resource group:  $($outputs.resourceGroupName.value)"
Write-Host "  Function app:    $($outputs.functionAppName.value)"
Write-Host "  Front Door host: $($outputs.frontDoorHostName.value)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Authorize Logic App mail connector ($MailProvider) in Azure Portal"
Write-Host "  2. Set Function App BASILISK_BASE_URL to https://$($outputs.frontDoorHostName.value)"
Write-Host "  3. Publish function code (az functionapp deploy or azd deploy)"
