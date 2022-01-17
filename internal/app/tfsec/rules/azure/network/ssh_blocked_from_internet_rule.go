package network

import (
	"github.com/aquasecurity/defsec/rules/azure/network"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU017",
		BadExample: []string{`
 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = ["22"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
      network_security_group_name = azurerm_network_security_group.example.name
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_range      = ["22"]
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
      destination_port_range      = ["22"]
      source_address_prefix       = "82.102.23.23"
      destination_address_prefix  = "*"
      network_security_group_name = azurerm_network_security_group.example.name
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_range      = ["22"]
      source_address_prefix       = "82.102.23.23"
      destination_address_prefix  = "*"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule",
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_group", "azurerm_network_security_rule"},
		Base:           network.CheckSshBlockedFromInternet,
	})
}
