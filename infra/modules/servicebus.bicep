@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

var sbName = '${namePrefix}-bus'

resource namespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: sbName
  location: location
  sku: {
    name: 'Standard'
  }
}

resource keyEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'key-events'
}

resource sendtokenEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'sendtoken-events'
}

var ruleId = 'RootManageSharedAccessKey'
var authRule = listKeys('${namespace.id}/AuthorizationRules/${ruleId}', namespace.apiVersion)

output connectionString string = 'Endpoint=sb://${namespace.name}.servicebus.windows.net/;SharedAccessKeyName=${ruleId};SharedAccessKey=${authRule.primaryKey}'
