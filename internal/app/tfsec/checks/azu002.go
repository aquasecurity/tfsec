package checks

import (
	"fmt"
	"github.com/zclconf/go-cty/cty"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AzureOpenOutboundNetworkSecurityGroupRule scanner.RuleCode = "AZU002"
const AzureOpenOutboundNetworkSecurityGroupRuleDescription scanner.RuleSummary = "An outbound network security rule allows traffic to `/0`."
const AzureOpenOutboundNetworkSecurityGroupRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segements should be broken into smaller subnets.
`
const AzureOpenOutboundNetworkSecurityGroupRuleBadExample = `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`
const AzureOpenOutboundNetworkSecurityGroupRuleGoodExample = `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureOpenOutboundNetworkSecurityGroupRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureOpenOutboundNetworkSecurityGroupRuleDescription,
			Explanation: AzureOpenOutboundNetworkSecurityGroupRuleExplanation,
			BadExample:  AzureOpenOutboundNetworkSecurityGroupRuleBadExample,
			GoodExample: AzureOpenOutboundNetworkSecurityGroupRuleGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
				"https://www.terraform.io/docs/providers/azurerm/r/network_security_rule.html",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			directionAttr := block.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Outbound" {
				return nil
			}

			if prefixAttr := block.GetAttribute("destination_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if strings.HasSuffix(prefixAttr.Value().AsString(), "/0") || prefixAttr.Value().AsString() == "*" {
					if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									block.Name(),
									strings.ToLower(directionAttr.Value().AsString()),
								),
								prefixAttr.Range(),
								prefixAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}
			}

			var results []scanner.Result

			if prefixesAttr := block.GetAttribute("destination_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				for _, prefix := range prefixesAttr.Value().AsValueSlice() {
					if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*" {
						if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
							results = append(results,
								check.NewResultWithValueAnnotation(
									fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", block.Name(), prefix.AsString()),
									prefixesAttr.Range(),
									prefixesAttr,
									scanner.SeverityWarning,
								),
							)
						}
					}
				}

			}

			return results
		},
	})
}
