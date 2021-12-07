package datafactory
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AZUDataFactoryPublicNetwork(t *testing.T) {
// 	expectedCode := "azure-datafactory-no-public-access"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check if public_network_enabled not set, check fails",
// 			source: `
// resource "azurerm_data_factory" "bad_example" {
//   name                = "example"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check if public_network_enabled is set to false, check passes",
// 			source: `
// resource "azurerm_data_factory" "good_example" {
//   name                = "example"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
//   public_network_enabled = false
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check if public_network_enabled is set to true, check fails",
// 			source: `
// resource "azurerm_data_factory" "bad_example" {
//   name                = "example"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
//   public_network_enabled = true
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
