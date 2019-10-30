package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AzureUnencryptedDataLakeStore(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check azurerm_data_lake_store with encryption disabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Disabled"
}`,
			expectedResultCode: checks.AzureUnencryptedDataLakeStore,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	encryption_state = "Enabled"
}`,
			expectedResultCode: checks.None,
		},
		{
			name: "check azurerm_data_lake_store with encryption enabled by default",
			source: `
resource "azurerm_data_lake_store" "my-lake-store" {
	
}`,
			expectedResultCode: checks.None,
		},

	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
