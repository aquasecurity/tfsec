package compute
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AzureUnencryptedManagedDisk(t *testing.T) {
 	expectedCode := "azure-compute-enable-disk-encryption"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check azurerm_managed_disk with no encryption_settings",
 			source: `
 resource "azurerm_managed_disk" "my-disk" {
 	
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check azurerm_managed_disk with encryption disabled",
 			source: `
 resource "azurerm_managed_disk" "my-disk" {
 	encryption_settings {
 		enabled = false
 	}
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check azurerm_managed_disk with encryption enabled",
 			source: `
 resource "azurerm_managed_disk" "my-disk" {
 	encryption_settings {
 		enabled = true
 	}
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
