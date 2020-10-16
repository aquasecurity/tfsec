package azure

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AzureOpenInboundNetworkSecurityGroupRule See https://github.com/tfsec/tfsec#included-checks for check info
const AzureOpenInboundNetworkSecurityGroupRule scanner.RuleID = "AZU001"
const AzureOpenInboundNetworkSecurityGroupRuleDescription scanner.RuleSummary = "An inbound network security rule allows traffic from `/0`."
const AzureOpenInboundNetworkSecurityGroupRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segements should be broken into smaller subnets.
`
const AzureOpenInboundNetworkSecurityGroupRuleBadExample = `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`
const AzureOpenInboundNetworkSecurityGroupRuleGoodExample = `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AzureOpenInboundNetworkSecurityGroupRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AzureOpenInboundNetworkSecurityGroupRuleDescription,
			Explanation: AzureOpenInboundNetworkSecurityGroupRuleExplanation,
			BadExample:  AzureOpenInboundNetworkSecurityGroupRuleBadExample,
			GoodExample: AzureOpenInboundNetworkSecurityGroupRuleGoodExample,
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
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Inbound" {
				return nil
			}

			if prefixAttr := block.GetAttribute("source_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
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

			if prefixesAttr := block.GetAttribute("source_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
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
