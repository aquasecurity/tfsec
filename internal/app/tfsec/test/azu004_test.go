package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AzureUnencryptedDataLakeStore(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_data_lake_store with encryption disabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Disabled"
}`,
			mustIncludeResultCode: checks.AzureUnencryptedDataLakeStore,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Enabled"
}`,
			mustExcludeResultCode: checks.AzureUnencryptedDataLakeStore,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled by default",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	
}`,
			mustExcludeResultCode: checks.AzureUnencryptedDataLakeStore,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
