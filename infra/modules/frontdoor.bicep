@description('Resource name prefix')

param namePrefix string



@description('Storage account name')

param storageAccountName string



@description('Function app default hostname')

param functionHostName string



@description('Max POST /pks/add requests per IP per minute')

param uploadRateLimitPerMinute int = 10



@description('Max POST /pks/v2 requests per IP per minute')

param v2UploadRateLimitPerMinute int = 5



@description('Max sendtoken requests per IP per minute')

param sendtokenRateLimitPerMinute int = 3



@description('Optional ISO country codes to block (e.g. CN, RU)')

param blockedCountryCodes array = []



var fdProfile = '${namePrefix}-fd'

var wafPolicyName = '${namePrefix}waf'



resource frontDoor 'Microsoft.Cdn/profiles@2023-05-01' = {

  name: fdProfile

  location: 'global'

  sku: {

    name: 'Standard_AzureFrontDoor'

  }

}



resource wafPolicy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2022-05-01' = {

  name: wafPolicyName

  location: 'global'

  sku: {

    name: 'Standard_AzureFrontDoor'

  }

  properties: {

    policySettings: {

      enabledState: 'Enabled'

      mode: 'Prevention'

    }

    customRules: {

      rules: [

        {

          name: 'UploadRateLimit'

          enabledState: 'Enabled'

          priority: 100

          ruleType: 'RateLimitRule'

          rateLimitDurationInMinutes: 1

          rateLimitThreshold: uploadRateLimitPerMinute

          matchConditions: [

            {

              matchVariable: 'RequestUri'

              operator: 'Contains'

              negateCondition: false

              matchValue: ['/pks/add']

            }

            {

              matchVariable: 'RequestMethod'

              operator: 'Equal'

              negateCondition: false

              matchValue: ['POST']

            }

          ]

          action: 'Block'

        }

        {

          name: 'V2UploadRateLimit'

          enabledState: 'Enabled'

          priority: 110

          ruleType: 'RateLimitRule'

          rateLimitDurationInMinutes: 1

          rateLimitThreshold: v2UploadRateLimitPerMinute

          matchConditions: [

            {

              matchVariable: 'RequestUri'

              operator: 'Contains'

              negateCondition: false

              matchValue: ['/pks/v2/']

            }

            {

              matchVariable: 'RequestMethod'

              operator: 'Equal'

              negateCondition: false

              matchValue: ['POST', 'PUT']

            }

          ]

          action: 'Block'

        }

        {

          name: 'SendtokenRateLimit'

          enabledState: 'Enabled'

          priority: 120

          ruleType: 'RateLimitRule'

          rateLimitDurationInMinutes: 1

          rateLimitThreshold: sendtokenRateLimitPerMinute

          matchConditions: [

            {

              matchVariable: 'RequestUri'

              operator: 'Contains'

              negateCondition: false

              matchValue: ['/pks/v2/sendtoken']

            }

          ]

          action: 'Block'

        }

      ]

    }

  }

}



resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2023-05-01' = {

  parent: frontDoor

  name: 'basilisk-waf'

  properties: {

    parameters: {

      type: 'WebApplicationFirewall'

      wafPolicy: {

        id: wafPolicy.id

      }

      associations: [

        {

          domains: [

            {

              id: endpoint.id

            }

          ]

          patternsToMatch: ['/*']

        }

      ]

    }

  }

}



resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2023-05-01' = {

  parent: frontDoor

  name: '${namePrefix}-endpoint'

  location: 'global'

  properties: {

    enabledState: 'Enabled'

  }

}



var staticWebsiteHost = '${storageAccountName}.z.web.${environment().suffixes.storage}'



resource fnOriginGroup 'Microsoft.Cdn/profiles/originGroups@2023-05-01' = {

  parent: frontDoor

  name: 'basilisk-origins'

  properties: {

    loadBalancingSettings: {

      sampleSize: 4

      successfulSamplesRequired: 3

    }

    healthProbeSettings: {

      probePath: '/health'

      probeRequestType: 'GET'

      probeProtocol: 'Https'

      probeIntervalInSeconds: 120

    }

  }

}



resource fnOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2023-05-01' = {

  parent: fnOriginGroup

  name: 'function-origin'

  properties: {

    hostName: functionHostName

    httpPort: 80

    httpsPort: 443

    originHostHeader: functionHostName

    priority: 1

    weight: 1000

    enabledState: 'Enabled'

  }

}



resource staticOriginGroup 'Microsoft.Cdn/profiles/originGroups@2023-05-01' = {

  parent: frontDoor

  name: 'basilisk-static-origins'

  properties: {

    loadBalancingSettings: {

      sampleSize: 4

      successfulSamplesRequired: 3

    }

    healthProbeSettings: {

      probePath: '/index.html'

      probeRequestType: 'GET'

      probeProtocol: 'Https'

      probeIntervalInSeconds: 240

    }

  }

}



resource staticOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2023-05-01' = {

  parent: staticOriginGroup

  name: 'static-origin'

  properties: {

    hostName: staticWebsiteHost

    httpPort: 80

    httpsPort: 443

    originHostHeader: staticWebsiteHost

    priority: 1

    weight: 1000

    enabledState: 'Enabled'

  }

}



resource apiRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {

  parent: endpoint

  name: 'api-route'

  properties: {

    originGroup: { id: fnOriginGroup.id }

    supportedProtocols: ['Http', 'Https']

    patternsToMatch: ['/pks/*', '/api/*', '/claim/*', '/.auth/*', '/health']

    forwardingProtocol: 'HttpsOnly'

    linkToDefaultDomain: 'Enabled'

    httpsRedirect: 'Enabled'

    cacheConfiguration: {

      queryStringCachingBehavior: 'IgnoreQueryString'

      compressionSettings: {

        isCompressionEnabled: true

        contentTypesToCompress: ['text/plain']

      }

    }

  }

  dependsOn: [fnOrigin]

}



resource staticRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {

  parent: endpoint

  name: 'static-route'

  properties: {

    originGroup: { id: staticOriginGroup.id }

    supportedProtocols: ['Http', 'Https']

    patternsToMatch: ['/', '/*']

    forwardingProtocol: 'HttpsOnly'

    linkToDefaultDomain: 'Enabled'

    httpsRedirect: 'Enabled'

    cacheConfiguration: {

      queryStringCachingBehavior: 'UseQueryString'

      compressionSettings: {

        isCompressionEnabled: true

        contentTypesToCompress: ['text/html', 'text/css', 'application/javascript']

      }

    }

  }

  dependsOn: [staticOrigin]

}



output hostName string = endpoint.properties.hostName

output wafPolicyId string = wafPolicy.id


