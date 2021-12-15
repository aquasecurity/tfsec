package network

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU024",
		BadExample: []string{`
 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_range      = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
   }
 }
 `},
		GoodExample: []string{`
 resource "azurerm_network_security_rule" "good_example" {
      name                        = "good_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_range      = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule",
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges",
			"https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_group", "azurerm_network_security_rule"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			var securityRules block.Blocks
			if resourceBlock.IsResourceType("azurerm_network_security_group") {
				securityRules = resourceBlock.GetBlocks("security_rule")
			} else {
				securityRules = append(securityRules, resourceBlock)
			}

			for _, securityRule := range securityRules {
				if securityRule.HasChild("access") && securityRule.GetAttribute("access").Equals("Deny", block.IgnoreCase) {
					continue
				}
				if securityRule.HasChild("destination_port_range") && securityRule.GetAttribute("destination_port_range").Contains("3389") {
					if securityRule.HasChild("source_address_prefix") {
						sourceAddrAttr := securityRule.GetAttribute("source_address_prefix")
						if sourceAddrAttr.IsAny("*", "0.0.0.0", "/0", "internet", "any") {
							results.Add("Resource has a source address prefix of *, 0.0.0.0, /0, internet or an any. Consider using the Azure Bastion Service.", ?)
						}
					}
				}
			}
			return results
		},
	})
}
