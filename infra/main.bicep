targetScope = 'subscription'

@description('Resource name prefix')
param namePrefix string = 'basilisk'

@description('Azure region')
param location string = 'eastus'

@description('Entra tenant ID for Easy Auth')
param entraTenantId string

@description('Mail provider for Logic Apps: office365 or gmail')
@allowed(['office365', 'gmail'])
param mailProvider string = 'office365'

@description('Require manager approval (O365 only)')
param requireManagerApproval bool = false

var rgName = '${namePrefix}-rg'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: rgName
  location: location
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  scope: rg
  params: {
    namePrefix: namePrefix
    location: location
  }
}

module servicebus 'modules/servicebus.bicep' = {
  name: 'servicebus'
  scope: rg
  params: {
    namePrefix: namePrefix
    location: location
  }
}

module functions 'modules/functions.bicep' = {
  name: 'functions'
  scope: rg
  params: {
    namePrefix: namePrefix
    location: location
    entraTenantId: entraTenantId
    storageAccountName: storage.outputs.storageAccountName
    storageConnectionString: storage.outputs.connectionString
    serviceBusConnectionString: servicebus.outputs.connectionString
    requireManagerApproval: requireManagerApproval
  }
}

module logicapps 'modules/logicapps.bicep' = {
  name: 'logicapps'
  scope: rg
  params: {
    namePrefix: namePrefix
    location: location
    mailProvider: mailProvider
    requireManagerApproval: requireManagerApproval
    serviceBusConnectionString: servicebus.outputs.connectionString
  }
}

module frontdoor 'modules/frontdoor.bicep' = {
  name: 'frontdoor'
  scope: rg
  params: {
    namePrefix: namePrefix
    storageAccountName: storage.outputs.storageAccountName
    functionHostName: functions.outputs.defaultHostName
    uploadRateLimitPerMinute: 10
    v2UploadRateLimitPerMinute: 5
    sendtokenRateLimitPerMinute: 3
  }
}

module rbac 'modules/rbac.bicep' = {
  name: 'rbac'
  scope: rg
  params: {
    storageAccountName: storage.outputs.storageAccountName
    functionPrincipalId: functions.outputs.principalId
  }
}

output resourceGroupName string = rg.name
output functionAppName string = functions.outputs.functionAppName
output frontDoorHostName string = frontdoor.outputs.hostName
