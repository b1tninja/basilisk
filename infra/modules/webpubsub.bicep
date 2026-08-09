@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

@description('Hub name for quorum signalling; must match BASILISK_WEBPUBSUB_HUB')
param hubName string = 'quorum'

// Free_F1 is the deliberate starting point: quorum signalling is a handful of
// short-lived connections carrying a few sealed envelopes each, and the tier's
// ceilings (20 concurrent connections, 20 000 messages/day) are the honest
// limit of this design rather than an oversight. Signalling moves to the peer
// data channels as soon as a pair meshes, which is what keeps the message
// count proportional to *peers* rather than to conversation length. A
// deployment expecting more than a few simultaneous rooms should move to
// Standard_S1 — nothing in the application changes.
//
// Two things now spend that connection budget on purpose. Clients recycle the
// signalling connection at 80% of their grant's life, joining the replacement
// before closing the original, so a peer counts twice for the length of one
// handshake. And a room rotation moves everyone to a new group, which is a new
// connection each. Both are bounded and short; neither raises the *steady*
// count, which is still one connection per peer in a live room.
resource webPubSub 'Microsoft.SignalRService/webPubSub@2023-02-01' = {
  name: '${namePrefix}-wps'
  location: location
  sku: {
    name: 'Free_F1'
    tier: 'Free'
    capacity: 1
  }
  properties: {
    // No upstream event handlers: clients publish to each other directly under
    // the token's group roles, and the server never sees a signalling message.
    // Anonymous connect is off — every connection presents a token this app
    // minted for one room.
    disableAadAuth: false
    disableLocalAuth: false
    publicNetworkAccess: 'Enabled'
    tls: {
      clientCertEnabled: false
    }
  }
}

resource hub 'Microsoft.SignalRService/webPubSub/hubs@2023-02-01' = {
  parent: webPubSub
  name: hubName
  properties: {
    anonymousConnectPolicy: 'deny'
    eventHandlers: []
  }
}

output name string = webPubSub.name
output hostName string = webPubSub.properties.hostName
output hubName string = hub.name

@description('Connection string for AZURE_WEBPUBSUB_CONNECTION_STRING')
#disable-next-line outputs-should-not-contain-secrets
output connectionString string = webPubSub.listKeys().primaryConnectionString
