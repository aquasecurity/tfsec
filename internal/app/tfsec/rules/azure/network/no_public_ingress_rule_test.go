package network
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AzureOpenNetworkSecurityGroupRule(t *testing.T) {
// 	expectedIngressCode := "azure-network-no-public-ingress"
// 	expectedEgressCode := "azure-network-no-public-egress"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Inbound"
// 	source_address_prefix = "0.0.0.0/0"
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedIngressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule inbound on *",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Inbound"
// 	source_address_prefix = "*"
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedIngressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0 in list",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Inbound"
// 	source_address_prefixes = ["0.0.0.0/0"]
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedIngressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule inbound on * in list",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Inbound"
// 	source_address_prefixes = ["*"]
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedIngressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Outbound"
// 	destination_address_prefix = "0.0.0.0/0"
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedEgressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule outbound on 0.0.0.0/0 in list",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Outbound"
// 	destination_address_prefixes = ["0.0.0.0/0"]
// 	access = "Allow"
// }`,
// 			mustIncludeResultCode: expectedEgressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule outbound on 10.0.0.0/16",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Outbound"
// 	destination_address_prefix = "10.0.0.0/16"
// 	access = "Allow"
// }`,
// 			mustExcludeResultCode: expectedEgressCode,
// 		},
// 		{
// 			name: "check azurerm_network_security_rule inbound on 0.0.0.0/0",
// 			source: `
// resource "azurerm_network_security_rule" "my-rule" {
// 	direction = "Inbound"
// 	source_address_prefix = "0.0.0.0/0"
// 	access = "Deny"
// }`,
// 			mustExcludeResultCode: expectedIngressCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
