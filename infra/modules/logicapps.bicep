@description('Resource name prefix')
param namePrefix string

@description('Azure region')
param location string

@description('Mail provider')
param mailProvider string

@description('Require manager approval')
param requireManagerApproval bool

@secure()
param serviceBusConnectionString string

var laName = '${namePrefix}-approval-la'

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: laName
  location: location
  properties: {
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        mailProvider: { type: 'String', defaultValue: mailProvider }
        '$connections': { type: 'Object', defaultValue: {} }
      }
      triggers: {
        When_message_in_queue: {
          recurrence: {
            frequency: 'Second'
            interval: 30
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'servicebus\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/@{encodeURIComponent(encodeURIComponent(\'key-events\'))}/messages/head'
            queries: {
              queueType: 'Main'
            }
          }
        }
      }
      actions: {
        Parse_message: {
          type: 'ParseJson'
          inputs: {
            content: '@json(base64ToString(triggerBody()?[\'ContentData\']))'
            schema: { type: 'object' }
          }
          runAfter: {}
        }
        Switch_event: {
          type: 'Switch'
          expression: '@body(\'Parse_message\')?[\'event\']'
          cases: {
            key_pending: {
              case: 'key.pending'
              actions: {
                Send_notification: {
                  type: 'Switch'
                  expression: '@parameters(\'mailProvider\')'
                  cases: {
                    office365: {
                      case: 'office365'
                      actions: {
                        Send_O365: {
                          type: 'ApiConnection'
                          inputs: {
                            host: { connection: { name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']' } }
                            method: 'post'
                            path: '/v2/Mail'
                            body: {
                              To: '@body(\'Parse_message\')?[\'uids\']'
                              Subject: 'Verify your OpenPGP key'
                              Body: '@body(\'Parse_message\')?[\'claim_url\']'
                            }
                          }
                        }
                      }
                    }
                    gmail: {
                      case: 'gmail'
                      actions: {
                        Send_Gmail: {
                          type: 'ApiConnection'
                          inputs: {
                            host: { connection: { name: '@parameters(\'$connections\')[\'gmail\'][\'connectionId\']' } }
                            method: 'post'
                            path: '/v2/Mail'
                            body: {
                              To: '@body(\'Parse_message\')?[\'uids\']'
                              Subject: 'Verify your OpenPGP key'
                              Body: '@body(\'Parse_message\')?[\'claim_url\']'
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            claim_submitted: {
              case: 'claim.submitted'
              actions: {
                Build_approved: {
                  type: 'Compose'
                  inputs: {
                    event: 'key.approved'
                    fingerprint: '@body(\'Parse_message\')?[\'fingerprint\']'
                    approved_uids: '@body(\'Parse_message\')?[\'matched_uids\']'
                  }
                  runAfter: {}
                }
                Send_approved: {
                  type: 'ApiConnection'
                  inputs: {
                    host: { connection: { name: '@parameters(\'$connections\')[\'servicebus\'][\'connectionId\']' } }
                    method: 'post'
                    path: '/@{encodeURIComponent(encodeURIComponent(\'key-approved\'))}/messages'
                    body: {
                      ContentData: '@{base64(string(outputs(\'Build_approved\')))}'
                    }
                  }
                  runAfter: {
                    Build_approved: ['Succeeded']
                  }
                }
              }
            }
          }
          default: { actions: {} }
          runAfter: { Parse_message: ['Succeeded'] }
        }
      }
    }
    parameters: {
      '$connections': { value: {} }
    }
  }
}

output logicAppName string = logicApp.name
