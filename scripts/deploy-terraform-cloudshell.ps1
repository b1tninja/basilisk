<#
.SYNOPSIS
  Deploy Basilisk with Terraform (Cloud Shell or local).

.EXAMPLE
  az login
  .\scripts\deploy-terraform-cloudshell.ps1

.EXAMPLE
  .\scripts\deploy-terraform-cloudshell.ps1 -NamePrefix basilisk-dev -AutoApprove
#>
[CmdletBinding()]
param(
    [string]$NamePrefix = "basilisk-dev",
    [string]$Location = "",
    [ValidateSet("office365", "gmail")]
    [string]$MailProvider = "office365",
    [string]$SubscriptionId = "",
    [switch]$AutoApprove
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$TfDir = Join-Path $RepoRoot "terraform\cloudshell"

function Assert-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Resolve-DeployLocation {
    param([string]$Prefix, [string]$Requested)
    if ($Requested) { return $Requested }

    $rgName = "${Prefix}-rg"
    $existing = az group show --name $rgName --query location -o tsv 2>$null
    if ($existing) {
        Write-Host "Using location from existing resource group: $rgName -> $existing"
        return $existing.Trim()
    }

    $configured = az config get defaults.location -o tsv 2>$null
    if ($configured) {
        Write-Host "Using az config defaults.location: $configured"
        return $configured.Trim()
    }

    Write-Host "No location specified; falling back to eastus (override with -Location)"
    return "eastus"
}

Assert-Command az
Assert-Command terraform

if (-not (az account show 2>$null)) {
    throw "Not logged in to Azure. Run: az login"
}

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId | Out-Null
}

$Location = Resolve-DeployLocation -Prefix $NamePrefix -Requested $Location
$tenantId = az account show --query tenantId -o tsv
$subName = az account show --query name -o tsv

Write-Host "Subscription: $subName"
Write-Host "Tenant:       $tenantId"
Write-Host "Name prefix:  $NamePrefix"
Write-Host "Location:     $Location"

$env:TF_VAR_name_prefix = $NamePrefix
$env:TF_VAR_location = $Location
$env:TF_VAR_mail_provider = $MailProvider

Push-Location $TfDir
try {
    terraform init -input=false

    $planArgs = @("plan", "-input=false", "-out=tfplan")
    if (Test-Path "terraform.tfvars") {
        $planArgs += @("-var-file=terraform.tfvars")
    }
    terraform @planArgs

    if ($AutoApprove) {
        terraform apply -input=false -auto-approve tfplan
    } else {
        terraform apply -input=false tfplan
    }

    $rg = terraform output -raw resource_group_name
    $fn = terraform output -raw function_app_name
    $fdUrl = terraform output -raw front_door_url

    az functionapp config appsettings set `
        --resource-group $rg `
        --name $fn `
        --settings "BASILISK_BASE_URL=$fdUrl" `
        --output none

    Write-Host ""
    Write-Host "Terraform deployment complete." -ForegroundColor Green
    Write-Host "  Resource group:  $rg"
    Write-Host "  Function app:    $fn"
    Write-Host "  Front Door URL:  $fdUrl"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Authorize Logic App mail connector ($MailProvider) in Azure Portal"
    Write-Host "  2. Publish function code (az functionapp deploy)"
    Write-Host "  3. Smoke test: curl $fdUrl/health"
    Write-Host "  4. Export GitHub secrets: .\scripts\export-github-secrets.ps1"
}
finally {
    Pop-Location
}
