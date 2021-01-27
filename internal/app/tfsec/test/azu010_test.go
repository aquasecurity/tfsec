package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUStorageAccountHTTPSenabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_storage_account with no enable_https_traffic_only define",
			source: `
resource "azurerm_storage_account" "my-storage-account" {

}`,
mustExcludeResultCode: checks.AZUStorageAccountHTTPSenabled,
		},
		{
			name: "check azurerm_storage_account with enable_https_traffic_only disabled",
			source: `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = false
}`,
			mustIncludeResultCode: checks.AZUStorageAccountHTTPSenabled,
		},
		{
			name: "check azurerm_storage_account with enable_https_traffic_only enabled",
			source: `
resource "azurerm_storage_account" "my-storage-account" {
	enable_https_traffic_only = true
}`,
			mustExcludeResultCode: checks.AZUStorageAccountHTTPSenabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
