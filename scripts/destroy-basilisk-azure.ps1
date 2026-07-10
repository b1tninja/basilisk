<#
.SYNOPSIS
  Delete Basilisk Azure resources (resource group and everything inside).

.EXAMPLE
  .\scripts\destroy-basilisk-azure.ps1
  .\scripts\destroy-basilisk-azure.ps1 -NamePrefix basilisk-prod
#>
[CmdletBinding()]
param(
    [string]$NamePrefix = "basilisk-dev",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$RgName = "${NamePrefix}-rg"

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI ('az') not found."
}

$exists = az group exists --name $RgName -o tsv
if ($exists -ne "true") {
    Write-Host "Resource group not found: $RgName"
    exit 0
}

Write-Host "Resources in $RgName :"
az resource list -g $RgName --query "[].{name:name,type:type}" -o table

if (-not $Force) {
    $confirm = Read-Host "Delete resource group '$RgName' and all contents? [y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled."
        exit 0
    }
}

Write-Host "Deleting $RgName ..."
az group delete --name $RgName --yes --no-wait
Write-Host "Delete initiated. Wait a minute, then re-run terraform apply."
