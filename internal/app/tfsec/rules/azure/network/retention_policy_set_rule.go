package network

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "network",
		ShortCode: "retention-policy-set",
		Documentation: rule.RuleDocumentation{
			Summary: "Retention policy for flow logs should be enabled and set to greater than 90 days",
			Explanation: `Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.`,
			Impact:     "Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis",
			Resolution: "Ensure flow log retention is turned on with an expiry of >90 days",
			BadExample: []string{`
resource "azurerm_network_watcher_flow_log" "bad_watcher" {
  network_watcher_name = "bad_watcher"
  resource_group_name  = "resource-group"

  network_security_group_id = azurerm_network_security_group.test.id
  storage_account_id        = azurerm_storage_account.test.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 7
  }
}
`},
			GoodExample: []string{`
resource "azurerm_network_watcher_flow_log" "good_watcher" {
  network_watcher_name = "good_watcher"
  resource_group_name  = "resource-group"

  network_security_group_id = azurerm_network_security_group.test.id
  storage_account_id        = azurerm_storage_account.test.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 90
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy",
				"https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_network_watcher_flow_log"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("retention_policy") {
				set.AddResult().
					WithDescription("Resource '%s' is missing the required retention policy block", resourceBlock.FullName())
				return
			}

			retentionPolicyBlock := resourceBlock.GetBlock("retention_policy")
			if retentionPolicyBlock.MissingChild("enabled") || retentionPolicyBlock.MissingChild("days") {
				set.AddResult().
					WithDescription("Resource '%s' is missing the required attributes retention policy block", resourceBlock.FullName())
				return
			}

			enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
			daysAttr := retentionPolicyBlock.GetAttribute("days")

			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has retention policy turned off", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}

			if daysAttr.LessThan(90) {
				set.AddResult().
					WithDescription("Resource '%s' has retention policy period of less than 90 days", resourceBlock.FullName()).
					WithAttribute(daysAttr)
			}
		},
	})
}
