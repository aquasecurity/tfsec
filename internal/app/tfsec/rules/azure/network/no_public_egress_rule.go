package network

import (
	"strings"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU002",
		BadExample: []string{`
 resource "azurerm_network_security_rule" "bad_example" {
 	direction = "Outbound"
 	destination_address_prefix = "0.0.0.0/0"
 	access = "Allow"
 }`},
		GoodExample: []string{`
 resource "azurerm_network_security_rule" "good_example" {
 	direction = "Outbound"
 	destination_address_prefix = "10.0.0.0/16"
 	access = "Allow"
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule",
			"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			directionAttr := resourceBlock.GetAttribute("direction")
			if directionAttr.IsNil() || directionAttr.Type() != cty.String || strings.ToUpper(directionAttr.Value().AsString()) != "OUTBOUND" {
				return
			}

			if prefixAttr := resourceBlock.GetAttribute("destination_address_prefix"); prefixAttr.IsString() {
				if cidr.IsAttributeOpen(prefixAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr.IsNotNil() && strings.ToUpper(accessAttr.Value().AsString()) == "ALLOW" {
						results.Add("Resource defines a fully open %s network security group rule.", resourceBlock.FullName(), strings.ToLower(directionAttr.Value().AsString()))
					}
				}
			}

			if prefixesAttr := resourceBlock.GetAttribute("destination_address_prefixes"); !prefixesAttr.IsEmpty() {
				if cidr.IsAttributeOpen(prefixesAttr) {
					if accessAttr := resourceBlock.GetAttribute("access"); accessAttr.IsNotNil() && strings.ToUpper(accessAttr.Value().AsString()) == "ALLOW" {
						results.Add("Resource defines a fully open security group rule.", ?)
					}
				}
			}

			return results
		},
	})
}
