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

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU001",
		Service:   "network",
		ShortCode: "no-public-ingress",
		Documentation: rule.RuleDocumentation{
			Summary:    "An inbound network security rule allows traffic from /0.",
			Impact:     "The port is exposed for ingress from the internet",
			Resolution: "Set a more restrictive cidr range",
			Explanation: `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets.
`,
			BadExample: `
resource "azurerm_network_security_rule" "bad_example" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`,
			GoodExample: `
resource "azurerm_network_security_rule" "good_example" {
	direction = "Inbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule",
				"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_network_security_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			directionAttr := resourceBlock.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || strings.ToUpper(directionAttr.Value().AsString()) != "INBOUND" {
				return
			}

			if prefixAttr := resourceBlock.GetAttribute("source_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
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

			if prefixesAttr := resourceBlock.GetAttribute("source_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
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
