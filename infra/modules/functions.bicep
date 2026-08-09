@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

@description('Entra tenant ID')
param entraTenantId string

@description('Storage account name')
param storageAccountName string

@secure()
param storageConnectionString string

@secure()
param serviceBusConnectionString string

@secure()
@description('Web PubSub connection string used to mint room-scoped signalling tokens')
param webPubSubConnectionString string = ''

@description('Web PubSub hub carrying quorum signalling')
param webPubSubHub string = 'quorum'

@description('Require manager approval before publishing keys')
param requireManagerApproval bool = false

var planName = '${namePrefix}-plan'
var appName = '${namePrefix}-fn'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  kind: 'functionapp'
  properties: {}
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    siteConfig: {
      linuxFxVersion: 'Python|3.13'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: storageConnectionString }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'ServiceBusConnection', value: serviceBusConnectionString }
        { name: 'AZURE_STORAGE_CONNECTION_STRING', value: storageConnectionString }
        { name: 'AZURE_WEBPUBSUB_CONNECTION_STRING', value: webPubSubConnectionString }
        { name: 'BASILISK_WEBPUBSUB_HUB', value: webPubSubHub }
        { name: 'BASILISK_CACHE_MODE', value: 'redirect' }
        { name: 'BASILISK_REQUIRE_MANAGER_APPROVAL', value: string(requireManagerApproval) }
      ]
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccountName}/deployments'
          authentication: { type: 'SystemAssignedIdentity' }
        }
      }
      scaleAndConcurrency: {
        alwaysReady: [{ name: 'http', instanceCount: 1 }]
      }
    }
  }
}

resource auth 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'AllowAnonymous'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: 'https://login.microsoftonline.com/${entraTenantId}/v2.0'
          clientId: '00000000-0000-0000-0000-000000000000'
        }
      }
    }
  }
}

output functionAppName string = functionApp.name
output defaultHostName string = functionApp.properties.defaultHostName
output principalId string = functionApp.identity.principalId
