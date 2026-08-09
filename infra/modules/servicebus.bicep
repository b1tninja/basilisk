@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

var sbName = '${namePrefix}-bus'

// Basic bills per operation with no namespace base charge; Standard adds a fixed
// monthly fee for topics, sessions, duplicate detection and scheduled delivery.
// This namespace carries three plain queues and uses none of those, so Basic is
// the cheaper tier and the intended end state.
//
// It is still Standard here, deliberately. A downgrade is refused while any
// queue holds a TTL above Basic's 14-day ceiling, and these queues inherited
// Standard's TimeSpan.MaxValue default. The queues cannot be fixed in the same
// deployment that moves the SKU -- they are children of the namespace, so the
// namespace goes first and 409s. Land `defaultMessageTimeToLive` first, then
// flip this to 'Basic' in a second deployment.
@description('Service Bus tier. Basic has no namespace base charge and carries queues only. Reachable only once a deployment has landed the queue TTLs below; if those are ever raised past 14 days this must go back to Standard first.')
@allowed(['Basic', 'Standard', 'Premium'])
param serviceBusSku string = 'Basic'

resource namespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: sbName
  location: location
  sku: {
    name: serviceBusSku
  }
}

// Declared, because the default is not portable between tiers: unset, a queue
// inherits Standard's TimeSpan.MaxValue (P10675199DT2H48M5.4775807S -- forever),
// which Basic refuses. 14 days is Basic's ceiling, so this is the smallest
// change to existing behaviour. These carry key-ingest and mail events that
// Logic Apps consume within seconds; a message still here after two weeks is
// not one anybody wants delivered.
var queueTtl = 'P14D'

resource keyEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'key-events'
  properties: {
    defaultMessageTimeToLive: queueTtl
  }
}

resource keyApproved 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'key-approved'
  properties: {
    defaultMessageTimeToLive: queueTtl
  }
}

resource sendtokenEvents 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'sendtoken-events'
  properties: {
    defaultMessageTimeToLive: queueTtl
  }
}

var ruleId = 'RootManageSharedAccessKey'
var authRule = listKeys('${namespace.id}/AuthorizationRules/${ruleId}', namespace.apiVersion)

output connectionString string = 'Endpoint=sb://${namespace.name}.servicebus.windows.net/;SharedAccessKeyName=${ruleId};SharedAccessKey=${authRule.primaryKey}'
