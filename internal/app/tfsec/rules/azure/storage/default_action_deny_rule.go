package storage

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
		LegacyID:  "AZU012",
		Service:   "storage",
		ShortCode: "default-action-deny",
		Documentation: rule.RuleDocumentation{
			Summary:    "The default action on Storage account network rules should be set to deny",
			Impact:     "Network rules that allow could cause data to be exposed publicly",
			Resolution: "Set network rules to deny",
			Explanation: `
The default_action for network rules should come into effect when no other rules are matched.

The default action should be set to Deny.
`,
			BadExample: []string{`
resource "azurerm_storage_account_network_rules" "bad_example" {
  
  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`},
			GoodExample: []string{`
resource "azurerm_storage_account_network_rules" "good_example" {
  
  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action",
				"https://docs.microsoft.com/en-us/azure/firewall/rule-processing",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account", "azurerm_storage_account_network_rules"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx block.Module) {

			blockName := resourceBlock.FullName()

			if resourceBlock.IsResourceType("azurerm_storage_account") {
				if resourceBlock.MissingChild("network_rules") &&
					len(ctx.GetResourcesByType("azurerm_storage_account_network_rules")) == 0				{
					set.AddResult().
						WithDescription("Resource '%s' does not have network_rules and there isn't a configured `azurerm_storage_account_network_rules.", blockName)
					return
				}
				resourceBlock = resourceBlock.GetBlock("network_rules")
			}

			defaultAction := resourceBlock.GetAttribute("default_action")
			if defaultAction.IsNotNil() && defaultAction.Equals("Allow", block.IgnoreCase) {
				set.AddResult().
					WithDescription("Resource '%s' defines a default_action of Allow. It should be Deny.", blockName)
			}

		},
	})
}
