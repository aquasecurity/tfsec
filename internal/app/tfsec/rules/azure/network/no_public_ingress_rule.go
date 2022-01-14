package network

import (
	"github.com/aquasecurity/defsec/rules/azure/network"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU001",
		BadExample: []string{`
 resource "azurerm_network_security_group" "example" {
	name                = "acceptanceTestSecurityGroup1"
 }

 resource "azurerm_network_security_rule" "bad_example" {
 	direction = "Inbound"
 	source_address_prefix = "0.0.0.0/0"
 	access = "Allow"
	network_security_group_name = azurerm_network_security_group.example.name
 }`},
		GoodExample: []string{`
 resource "azurerm_network_security_group" "example" {
	name                = "acceptanceTestSecurityGroup1"
 }

 resource "azurerm_network_security_rule" "good_example" {
 	direction = "Inbound"
 	destination_address_prefix = "10.0.0.0/16"
 	access = "Allow"
	network_security_group_name = azurerm_network_security_group.example.name
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		Base:           network.CheckNoPublicIngress,
	})
}
