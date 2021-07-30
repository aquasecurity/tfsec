package storage

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUTrustedMicrosoftServicesHaveStroageAccountAccess(t *testing.T) {
	expectedCode := "azure-storage-allow-microsoft-service-bypass"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
