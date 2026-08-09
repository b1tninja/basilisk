@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

var sbName = '${namePrefix}-bus'

// Basic bills per operation with no namespace base charge; Standard adds a fixed
// monthly fee for topics, sessions, duplicate detection and scheduled delivery.
// This namespace carries three plain queues and uses none of those, so Basic is
// the cheaper tier with no loss. Raise to Standard if a topic is ever introduced.
resource namespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: sbName
  location: location
  sku: {
    name: 'Basic'
  }
}

resource keyEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'key-events'
}

resource keyApproved 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'key-approved'
}

resource sendtokenEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'sendtoken-events'
}

var ruleId = 'RootManageSharedAccessKey'
var authRule = listKeys('${namespace.id}/AuthorizationRules/${ruleId}', namespace.apiVersion)

output connectionString string = 'Endpoint=sb://${namespace.name}.servicebus.windows.net/;SharedAccessKeyName=${ruleId};SharedAccessKey=${authRule.primaryKey}'
