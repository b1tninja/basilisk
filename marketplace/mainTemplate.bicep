targetScope = 'subscription'

@description('Resource name prefix')
param namePrefix string = 'basilisk'

@description('Azure region')
param location string = resourceGroup().location

@description('Entra tenant ID')
param entraTenantId string

@description('Mail provider')
@allowed(['office365', 'gmail'])
param mailProvider string = 'office365'

@description('Require manager approval (O365 only)')
param requireManagerApproval bool = false

var rgName = '${namePrefix}-rg'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: rgName
  location: location
}

module main '../infra/main.bicep' = {
  name: 'basilisk-deploy'
  params: {
    namePrefix: namePrefix
    location: location
    entraTenantId: entraTenantId
    mailProvider: mailProvider
    requireManagerApproval: requireManagerApproval
  }
}

output functionAppName string = main.outputs.functionAppName
output frontDoorHostName string = main.outputs.frontDoorHostName
