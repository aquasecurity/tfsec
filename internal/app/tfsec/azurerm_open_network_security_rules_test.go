package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/azure"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AzureOpenNetworkSecurityGroupRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on *",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "*"
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0 in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefixes = ["0.0.0.0/0"]
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on * in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefixes = ["*"]
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefix = "0.0.0.0/0"
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenOutboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0 in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefixes = ["0.0.0.0/0"]
	access = "Allow"
}`,
			mustIncludeResultCode: azure.AzureOpenOutboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 10.0.0.0/16",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefix = "10.0.0.0/16"
	access = "Allow"
}`,
			mustExcludeResultCode: azure.AzureOpenOutboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
	access = "Deny"
}`,
			mustExcludeResultCode: azure.AzureOpenInboundNetworkSecurityGroupRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
