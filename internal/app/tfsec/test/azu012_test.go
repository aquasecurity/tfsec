package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUDefaultActionOnNetworkRuleSetToDeny(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check default action of allow causes a failure",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
  
  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`,
			mustIncludeResultCode: checks.AZUDefaultActionOnNetworkRuleSetToDeny,
		},
		{
			name: "check default action of allow causes a failure, regardless of casing",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
  
  default_action             = "allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`,
			mustIncludeResultCode: checks.AZUDefaultActionOnNetworkRuleSetToDeny,
		},
		{
			name: "check default action of Allow on storage account causes a failure",
			source: `
resource "azurerm_storage_account" "example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Allow"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }

  tags = {
    environment = "staging"
  }
}
`,
			mustIncludeResultCode: checks.AZUDefaultActionOnNetworkRuleSetToDeny,
		},
		{
			name: "check no error when the default action is set to deny",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
  
  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`,
			mustExcludeResultCode: checks.AZUDefaultActionOnNetworkRuleSetToDeny,
		},
		{
			name: "check no error when the default action is set to deny, regardless of case",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
  
  default_action             = "deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`,
			mustExcludeResultCode: checks.AZUDefaultActionOnNetworkRuleSetToDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
