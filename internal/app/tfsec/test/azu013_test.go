package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUTrustedMicrosoftServicesHaveStroageAccountAccess(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check storage account without MicrosoftServices causes failure",
			source: `
resource "azurerm_storage_account" "example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
	bypass                     = ["Metrics"]
  }

  tags = {
    environment = "staging"
  }
}
`,
			mustIncludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
		{
			name: "check storage account network rules without MicrosoftServices bypass causes failure",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
resource_group_name  = azurerm_resource_group.test.name
storage_account_name = azurerm_storage_account.test.name

	default_action             = "Allow"
	ip_rules                   = ["127.0.0.1"]
	virtual_network_subnet_ids = [azurerm_subnet.test.id]
	bypass                     = ["Metrics"]
}
`,
			mustIncludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
		{
			name: "check storage account network rules with empty bypass fails",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
resource_group_name  = azurerm_resource_group.test.name
storage_account_name = azurerm_storage_account.test.name

	default_action             = "Allow"
	ip_rules                   = ["127.0.0.1"]
	virtual_network_subnet_ids = [azurerm_subnet.test.id]
	bypass                     = []
}
`,
			mustIncludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
		{
			name: "check storage account that has MicrosoftServices bypass passes",
			source: `
resource "azurerm_storage_account" "example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }

  tags = {
    environment = "staging"
  }
}
`,
			mustExcludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
		{
			name: "check storage account with no network rules passes",
			source: `
resource "azurerm_storage_account" "example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    environment = "staging"
  }
}
`,
			mustExcludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
		{
			name: "check storage account network rules that has MicrosoftServices bypass passes",
			source: `
resource "azurerm_storage_account_network_rules" "test" {
resource_group_name  = azurerm_resource_group.test.name
storage_account_name = azurerm_storage_account.test.name

	default_action             = "Allow"
	ip_rules                   = ["127.0.0.1"]
	virtual_network_subnet_ids = [azurerm_subnet.test.id]
	bypass                     = ["Metrics", "AzureServices"]
}
`,
			mustExcludeResultCode: checks.AZUTrustedMicrosoftServicesHaveStroageAccountAccess,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
