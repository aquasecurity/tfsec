package storage

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZURequireSecureTransferForStorageAccounts(t *testing.T) {
	expectedCode := "azure-storage-enforce-https"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check the storage account with explicit enable_https_traffic_only set to false fails",
			source: `
resource "azurerm_storage_account" "example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = false
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check the storage account with no explicit enable_https_traffic_only set passes",
			source: `
resource "azurerm_storage_account" "example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check the storage account with explicit enable_https_traffic_only set to true passes",
			source: `
resource "azurerm_storage_account" "example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = true
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
