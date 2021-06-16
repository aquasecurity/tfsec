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

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// AzureOpenInboundNetworkSecurityGroupRule See https://github.com/tfsec/tfsec#included-checks for check info
const AzureOpenInboundNetworkSecurityGroupRule = "AZU001"
const AzureOpenInboundNetworkSecurityGroupRuleDescription = "An inbound network security rule allows traffic from /0."
const AzureOpenInboundNetworkSecurityGroupRuleImpact = "The port is exposed for ingress from the internet"
const AzureOpenInboundNetworkSecurityGroupRuleResolution = "Set a more restrictive cidr range"
const AzureOpenInboundNetworkSecurityGroupRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segements should be broken into smaller subnets.
`
const AzureOpenInboundNetworkSecurityGroupRuleBadExample = `
resource "azurerm_network_security_rule" "bad_example" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`
const AzureOpenInboundNetworkSecurityGroupRuleGoodExample = `
resource "azurerm_network_security_rule" "good_example" {
	direction = "Inbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AzureOpenInboundNetworkSecurityGroupRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AzureOpenInboundNetworkSecurityGroupRuleDescription,
			Impact:      AzureOpenInboundNetworkSecurityGroupRuleImpact,
			Resolution:  AzureOpenInboundNetworkSecurityGroupRuleResolution,
			Explanation: AzureOpenInboundNetworkSecurityGroupRuleExplanation,
			BadExample:  AzureOpenInboundNetworkSecurityGroupRuleBadExample,
			GoodExample: AzureOpenInboundNetworkSecurityGroupRuleGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
				"https://www.terraform.io/docs/providers/azurerm/r/network_security_rule.html",
			},
		},
		Provider:       provider.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {

			directionAttr := resourceBlock.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Inbound" {
			}

			if prefixAttr := resourceBlock.GetAttribute("source_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if isOpenCidr(prefixAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									resourceBlock.FullName(),
									strings.ToLower(directionAttr.Value().AsString()),
								)).
								WithRange(prefixAttr.Range()).
								WithAttributeAnnotation(prefixAttr).
								WithSeverity(severity.Warning),
						)
					}
				}
			}

			if prefixesAttr := resourceBlock.GetAttribute("source_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				if isOpenCidr(prefixesAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open security group rule.", resourceBlock.FullName())).
								WithRange(prefixesAttr.Range()).
								WithAttributeAnnotation(prefixesAttr).
								WithSeverity(severity.Warning),
						)
					}
				}
			}

		},
	})
}
