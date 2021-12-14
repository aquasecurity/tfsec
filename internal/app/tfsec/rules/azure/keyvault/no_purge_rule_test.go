package keyvault
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AZUKeyVaultPurgeProtection(t *testing.T) {
 	expectedCode := "azure-keyvault-no-purge"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check if purge_protection_enabled not set, check fails",
 			source: `
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = false
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check if purge_protection_enabled is set, check passes",
 			source: `
 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = true
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check if purge_protection_enabled and soft_delete_retention_days is not set, check fails",
 			source: `
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     purge_protection_enabled    = false
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check if purge_protection_enabled is set but soft_delete_retention_days is not set, check fails",
 			source: `
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     purge_protection_enabled    = true
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check if purge_protection_enabled is set but soft_delete_retention_days is not set, check fails",
 			source: `
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
 	soft_delete_retention_days  = 0
     purge_protection_enabled    = true
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 	}
 
 	for _, test := range tests {
 		t.Run(test.name, func(t *testing.T) {
 
 			results := testutil.ScanHCL(test.source, t)
 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
 		})
 	}
 
 }
