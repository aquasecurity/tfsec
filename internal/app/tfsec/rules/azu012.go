package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUDefaultActionOnNetworkRuleSetToDeny = "AZU012"
const AZUDefaultActionOnNetworkRuleSetToDenyDescription = "The default action on Storage account network rules should be set to deny"
const AZUDefaultActionOnNetworkRuleSetToDenyImpact = "Network rules that allow could cause data to be exposed publically"
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
		Provider:       provider.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"},
		CheckFunc: func(b *block.Block, _ *hclcontext.Context) []result.Result {

			if b.IsResourceType("azurerm_storage_account") {
				if b.MissingChild("network_rules") {
					return nil
				}
				b = b.GetBlock("network_rules")
			}

			defaultAction := b.GetAttribute("default_action")
			if defaultAction != nil && defaultAction.Equals("Allow", block.IgnoreCase) {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines a default_action of Allow. It should be Deny.", b.FullName()),
						b.Range(),
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
