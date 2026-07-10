# Azure Marketplace package

Build and validate:

```powershell
./scripts/package-marketplace.ps1
./scripts/validate-marketplace.ps1
```

Deploy to sandbox subscription:

```bash
az deployment group validate -g basilisk-sandbox -f marketplace/mainTemplate.bicep -p @marketplace/test-params.json
```

See [createUiDefinition.json](createUiDefinition.json) for wizard parameters including `mailProvider`.
