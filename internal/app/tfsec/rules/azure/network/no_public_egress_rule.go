package network

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU002",
		Service:   "network",
		ShortCode: "no-public-egress",
		Documentation: rule.RuleDocumentation{
			Summary:    "An outbound network security rule allows traffic to /0.",
			Impact:     "The port is exposed for egress to the internet",
			Resolution: "Set a more restrictive cidr range",
			Explanation: `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets.
`,
			BadExample: `
resource "azurerm_network_security_rule" "bad_example" {
	direction = "Outbound"
	destination_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`,
			GoodExample: `
resource "azurerm_network_security_rule" "good_example" {
	direction = "Outbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
				"https://www.terraform.io/docs/providers/azurerm/r/network_security_rule.html",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_network_security_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			directionAttr := resourceBlock.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || strings.ToUpper(directionAttr.Value().AsString()) != "OUTBOUND" {
				return
			}

			if prefixAttr := resourceBlock.GetAttribute("destination_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if cidr.IsOpen(prefixAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr != nil && strings.ToUpper(accessAttr.Value().AsString()) == "ALLOW" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									resourceBlock.FullName(),
									strings.ToLower(directionAttr.Value().AsString()),
								)).
								WithRange(prefixAttr.Range()).
								WithAttributeAnnotation(prefixAttr),
						)
					}
				}
			}

			if prefixesAttr := resourceBlock.GetAttribute("destination_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				if cidr.IsOpen(prefixesAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr != nil && strings.ToUpper(accessAttr.Value().AsString()) == "ALLOW" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open security group rule.", resourceBlock.FullName())).
								WithRange(prefixesAttr.Range()).
								WithAttributeAnnotation(prefixesAttr),
						)
					}
				}
			}

		},
	})
}
