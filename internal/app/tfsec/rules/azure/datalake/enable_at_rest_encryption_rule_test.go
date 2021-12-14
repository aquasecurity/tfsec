package datalake
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AzureUnencryptedDataLakeStore(t *testing.T) {
 	expectedCode := "azure-datalake-enable-at-rest-encryption"
 
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
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check azurerm_data_lake_store with encryption enabled",
 			source: `
 resource "azurerm_data_lake_store" "my-lake-store" {
 	encryption_state = "Enabled"
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check azurerm_data_lake_store with encryption enabled by default",
 			source: `
 resource "azurerm_data_lake_store" "my-lake-store" {
 	
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
