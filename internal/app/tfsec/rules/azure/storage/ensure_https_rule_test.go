package storage

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUStorageAccountHTTPSenabled(t *testing.T) {
	expectedCode := "azure-storage-ensure-https"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_storage_account with no enable_https_traffic_only define",
			source: `
resource "azurerm_storage_account" "my-storage-account" {

}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_storage_account with enable_https_traffic_only disabled",
			source: `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = false
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_storage_account with enable_https_traffic_only enabled",
			source: `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = true
}`,
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
