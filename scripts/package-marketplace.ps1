$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
$out = "marketplace/package"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Path $out | Out-Null
az bicep build --file infra/main.bicep --outfile "$out/mainTemplate.json"
Copy-Item marketplace/createUiDefinition.json "$out/"
Copy-Item marketplace/test-params.json "$out/"
Compress-Archive -Path "$out/*" -DestinationPath marketplace/basilisk-marketplace.zip -Force
Write-Host "Packaged marketplace/basilisk-marketplace.zip"
