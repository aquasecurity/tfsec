package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUDefaultActionOnNetworkRuleSetToDeny = "AZU012"
const AZUDefaultActionOnNetworkRuleSetToDenyDescription = "The default action on Storage account network rules should be set to deny"
const AZUDefaultActionOnNetworkRuleSetToDenyImpact = "Network rules that allow could cause data to be exposed publicly"
const AZUDefaultActionOnNetworkRuleSetToDenyResolution = "Set network rules to deny"
const AZUDefaultActionOnNetworkRuleSetToDenyExplanation = `
The default_action for network rules should come into effect when no other rules are matched.

The default action should be set to Deny.
`
const AZUDefaultActionOnNetworkRuleSetToDenyBadExample = `
resource "azurerm_storage_account_network_rules" "bad_example" {
  
  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`
const AZUDefaultActionOnNetworkRuleSetToDenyGoodExample = `
resource "azurerm_storage_account_network_rules" "good_example" {
  
  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUDefaultActionOnNetworkRuleSetToDeny,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUDefaultActionOnNetworkRuleSetToDenyDescription,
			Impact:      AZUDefaultActionOnNetworkRuleSetToDenyImpact,
			Resolution:  AZUDefaultActionOnNetworkRuleSetToDenyResolution,
			Explanation: AZUDefaultActionOnNetworkRuleSetToDenyExplanation,
			BadExample:  AZUDefaultActionOnNetworkRuleSetToDenyBadExample,
			GoodExample: AZUDefaultActionOnNetworkRuleSetToDenyGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action",
				"https://docs.microsoft.com/en-us/azure/firewall/rule-processing",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.IsResourceType("azurerm_storage_account") {
				if resourceBlock.MissingChild("network_rules") {
					return
				}
				resourceBlock = resourceBlock.GetBlock("network_rules")
			}

			defaultAction := resourceBlock.GetAttribute("default_action")
			if defaultAction != nil && defaultAction.Equals("Allow", block.IgnoreCase) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a default_action of Allow. It should be Deny.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}

		},
	})
}
