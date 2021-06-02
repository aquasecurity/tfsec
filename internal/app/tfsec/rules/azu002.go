package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AzureOpenOutboundNetworkSecurityGroupRule = "AZU002"
const AzureOpenOutboundNetworkSecurityGroupRuleDescription = "An outbound network security rule allows traffic to /0."
const AzureOpenOutboundNetworkSecurityGroupRuleImpact = "The port is exposed for egress to the internet"
const AzureOpenOutboundNetworkSecurityGroupRuleResolution = "Set a more restrictive cidr range"
const AzureOpenOutboundNetworkSecurityGroupRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets.
`
const AzureOpenOutboundNetworkSecurityGroupRuleBadExample = `
resource "azurerm_network_security_rule" "bad_example" {
	direction = "Outbound"
	destination_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`
const AzureOpenOutboundNetworkSecurityGroupRuleGoodExample = `
resource "azurerm_network_security_rule" "good_example" {
	direction = "Outbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AzureOpenOutboundNetworkSecurityGroupRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AzureOpenOutboundNetworkSecurityGroupRuleDescription,
			Impact:      AzureOpenOutboundNetworkSecurityGroupRuleImpact,
			Resolution:  AzureOpenOutboundNetworkSecurityGroupRuleResolution,
			Explanation: AzureOpenOutboundNetworkSecurityGroupRuleExplanation,
			BadExample:  AzureOpenOutboundNetworkSecurityGroupRuleBadExample,
			GoodExample: AzureOpenOutboundNetworkSecurityGroupRuleGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
				"https://www.terraform.io/docs/providers/azurerm/r/network_security_rule.html",
			},
		},
		Provider:       provider.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			directionAttr := block.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Outbound" {
				return nil
			}

			if prefixAttr := block.GetAttribute("destination_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if isOpenCidr(prefixAttr) {
					if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						set.Add(
							result.New().WithDescription(
								fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									block.FullName(),
									strings.ToLower(directionAttr.Value().AsString()),
								),
								prefixAttr.Range(),
								prefixAttr,
								severity.Warning,
							),
						}
					}
				}
			}

			var results []result.Result

			if prefixesAttr := block.GetAttribute("destination_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				if isOpenCidr(prefixesAttr) {
					if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						results = append(results,
							result.New().WithDescription(
								fmt.Sprintf("Resource '%s' defines a fully open security group rule.", block.FullName()),
								prefixesAttr.Range(),
								prefixesAttr,
								severity.Warning,
							),
						)
					}
				}
			}

			return results
		},
	})
}
