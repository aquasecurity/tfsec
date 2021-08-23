package appservice
// 
// // generator-locked
// import (
// 	"github.com/aquasecurity/defsec/result"
// 	"github.com/aquasecurity/defsec/severity"
// 
// 	"github.com/aquasecurity/defsec/provider"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
// 
// 	"github.com/aquasecurity/tfsec/pkg/rule"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
// )
// 
// func init() {
// 	scanner.RegisterCheckRule(rule.Rule{
// 		LegacyID:  "AZU028",
// 		Service:   "appservice",
// 		ShortCode: "enforce-https",
// 		Documentation: rule.RuleDocumentation{
// 			Summary: "Ensure the Function App can only be accessed via HTTPS. The default is false.",
// 			Explanation: `
// By default, clients can connect to function endpoints by using both HTTP or HTTPS. You should redirect HTTP to HTTPs because HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.
// `,
// 			Impact:     "Anyone can access the Function App using HTTP.",
// 			Resolution: "You can redirect all HTTP requests to the HTTPS port.",
// 			BadExample: []string{`
// resource "azurerm_function_app" "bad_example" {
//   name                       = "test-azure-functions"
//   location                   = azurerm_resource_group.example.location
//   resource_group_name        = azurerm_resource_group.example.name
//   app_service_plan_id        = azurerm_app_service_plan.example.id
//   storage_account_name       = azurerm_storage_account.example.name
//   storage_account_access_key = azurerm_storage_account.example.primary_access_key
//   os_type                    = "linux"
// }
// `},
// 			GoodExample: []string{`
// resource "azurerm_function_app" "good_example" {
//   name                       = "test-azure-functions"
//   location                   = azurerm_resource_group.example.location
//   resource_group_name        = azurerm_resource_group.example.name
//   app_service_plan_id        = azurerm_app_service_plan.example.id
//   storage_account_name       = azurerm_storage_account.example.name
//   storage_account_access_key = azurerm_storage_account.example.primary_access_key
//   os_type                    = "linux"
//   https_only                 = true
// }
// `},
// 			Links: []string{
// 				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only",
// 				"https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
// 				"https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts",
// 			},
// 		},
// 		Provider:        provider.AzureProvider,
// 		RequiredTypes:   []string{"resource"},
// 		RequiredLabels:  []string{"azurerm_function_app"},
// 		DefaultSeverity: severity.Critical,
// 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
// 
// 			if resourceBlock.MissingChild("https_only") {
// 				set.AddResult().
// 					WithDescription("Resource '%s' should have https_only set to true, the default is false.", resourceBlock.FullName())
// 				return
// 			}
// 			httpsOnlyAttr := resourceBlock.GetAttribute("https_only")
// 			if httpsOnlyAttr.IsFalse() {
// 				set.AddResult().
// 					WithDescription("Resource '%s' should have https_only set to true, the default is false.", resourceBlock.FullName()).
// 					WithAttribute("")
// 			}
// 		},
// 	})
// }
