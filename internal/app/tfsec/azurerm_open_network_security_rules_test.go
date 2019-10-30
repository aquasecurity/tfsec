package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AzureOpenNetworkSecurityGroupRule(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "0.0.0.0/0"
}`,
			expectedResultCode: checks.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on *",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefix = "*"
}`,
			expectedResultCode: checks.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0 in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefixes = ["0.0.0.0/0"]
}`,
			expectedResultCode: checks.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule inbound on * in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Inbound"
	source_address_prefixes = ["*"]
}`,
			expectedResultCode: checks.AzureOpenInboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefix = "0.0.0.0/0"
}`,
			expectedResultCode: checks.AzureOpenOutboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0 in list",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefixes = ["0.0.0.0/0"]
}`,
			expectedResultCode: checks.AzureOpenOutboundNetworkSecurityGroupRule,
		},
		{
			name: "check azurerm_network_security_rule outbound on 10.0.0.0/16",
			source: `
resource "azurerm_network_security_rule" "my-rule" {
	direction = "Outbound"
	destination_address_prefix = "10.0.0.0/16"
}`,
			expectedResultCode: checks.None,
		},

	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
