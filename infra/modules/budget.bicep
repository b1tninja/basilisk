@description('Resource name prefix')
param namePrefix string

@description('Monthly cost ceiling in the billing currency. Alerts only — a budget cannot stop spending. The hard stops are maximumInstanceCount, log_analytics_daily_quota_gb, and the Free/Basic SKUs; see docs/DEPLOYMENT.md.')
param budgetAmount int = 100

@description('Extra addresses to notify. The Owner role is always notified, so this may be empty.')
param budgetContactEmails array = []

@description('First day of the month the budget starts tracking. Azure requires the first of a month and rejects dates more than three months in the past.')
param budgetStartDate string = utcNow('yyyy-MM-01')

// Terraform grew this resource first (terraform/modules/basilisk/monitoring.tf).
// Bicep had no budget at all, which mattered because azure.yaml deploys through
// these templates -- so the azd path ran with no cost alerting whatsoever.
// Keep the two in step: same amount, same thresholds, same contacts.
resource budget 'Microsoft.Consumption/budgets@2023-05-01' = {
  name: '${namePrefix}-budget'
  properties: {
    category: 'Cost'
    amount: budgetAmount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: '${budgetStartDate}T00:00:00Z'
    }
    notifications: {
      // Actual spend, early warning.
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: budgetContactEmails
        contactRoles: ['Owner']
      }
      // Actual spend, ceiling reached.
      actual100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: budgetContactEmails
        contactRoles: ['Owner']
      }
      // Forecast, which is the one that arrives in time to act on. An actual-spend
      // alert tells you the money is already gone; a forecast alert fires while the
      // month still has room to change course.
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: budgetContactEmails
        contactRoles: ['Owner']
      }
    }
  }
}

output budgetName string = budget.name
