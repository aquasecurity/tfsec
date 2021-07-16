package storage

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUMinTLSForStorageAccountsSet(t *testing.T) {
	expectedCode := "azure-storage-use-secure-tls-policy"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check when min_tls not set check fails",
			source: `
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_0"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check when min_tls set to TLS1_0 check fails",
			source: `
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_0"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check when min_tls set to TLS1_1 check fails",
			source: `
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_1"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "TODO: add test name",
			source: `
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_2"
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
