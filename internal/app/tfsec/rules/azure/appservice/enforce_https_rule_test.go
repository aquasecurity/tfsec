package appservice
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AZUFunctionAppHTTPS(t *testing.T) {
 	expectedCode := "azure-appservice-enforce-https"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check if https_only not set, check fails",
 			source: `
 resource "azurerm_function_app" "bad_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check if https_only is set true, check passes",
 			source: `
 resource "azurerm_function_app" "good_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
   https_only                 = true
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check if https_only is set to false, check fails",
 			source: `
 resource "azurerm_function_app" "bad_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
   https_only                 = false
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
