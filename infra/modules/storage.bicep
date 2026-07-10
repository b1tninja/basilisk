@description('Resource name prefix')

param namePrefix string



@description('Azure region')

param location string



@description('Enable immutability policy on certs container')

param enableWormImmutability bool = true



@description('Immutability retention days for cert blobs')

param wormRetentionDays int = 365



var storageName = toLower(replace('${namePrefix}store', '-', ''))



resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {

  name: take(storageName, 24)

  location: location

  sku: {

    name: 'Standard_LRS'

  }

  kind: 'StorageV2'

  properties: {

    supportsHttpsTrafficOnly: true

    minimumTlsVersion: 'TLS1_2'

    allowBlobPublicAccess: false

  }

}



resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {

  parent: storageAccount

  name: 'default'

  properties: {

    deleteRetentionPolicy: {

      enabled: true

      days: 7

    }

    containerDeleteRetentionPolicy: {

      enabled: true

      days: 7

    }

    staticWebsite: {

      enabled: true

      indexDocument: 'index.html'

      error404Document: 'index.html'

    }

  }

}



resource certsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {

  parent: blobService

  name: 'certs'

  properties: {

    publicAccess: 'None'

    immutableStorageWithVersioning: {

      enabled: enableWormImmutability

    }

  }

}



resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {

  parent: storageAccount

  name: 'default'

}



resource wormPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (enableWormImmutability) {

  parent: certsContainer

  name: 'default'

  properties: {

    immutabilityPeriodSinceCreationInDays: wormRetentionDays

    allowProtectedAppendWrites: true

    allowProtectedAppendWritesAll: true

  }

}



output storageAccountName string = storageAccount.name

output staticWebsiteHost string = '${storageAccount.name}.z.web.${environment().suffixes.storage}'

output connectionString string = 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'


