package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AzureUnencryptedDataLakeStore(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_data_lake_store with encryption disabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Disabled"
}`,
			mustIncludeResultCode: rules.AzureUnencryptedDataLakeStore,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Enabled"
}`,
			mustExcludeResultCode: rules.AzureUnencryptedDataLakeStore,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled by default",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	
}`,
			mustExcludeResultCode: rules.AzureUnencryptedDataLakeStore,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
