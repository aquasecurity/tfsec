package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUDefaultActionOnNetworkRuleSetToDeny scanner.RuleCode = "AZU012"
const AZUDefaultActionOnNetworkRuleSetToDenyDescription scanner.RuleSummary = "The default action on Storage account network rules should be set to deny"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AZUDefaultActionOnNetworkRuleSetToDeny,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUDefaultActionOnNetworkRuleSetToDenyDescription,
			Explanation: AZUDefaultActionOnNetworkRuleSetToDenyExplanation,
			BadExample:  AZUDefaultActionOnNetworkRuleSetToDenyBadExample,
			GoodExample: AZUDefaultActionOnNetworkRuleSetToDenyGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action",
				"https://docs.microsoft.com/en-us/azure/firewall/rule-processing",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.IsResourceType("azurerm_storage_account") {
				if block.MissingChild("network_rules") {
					return nil
				}
				block = block.GetBlock("network_rules")
			}

			defaultAction := block.GetAttribute("default_action")
			if defaultAction != nil && defaultAction.Equals("Allow", parser.IgnoreCase) {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a default_action of Allow. It should be Deny.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
