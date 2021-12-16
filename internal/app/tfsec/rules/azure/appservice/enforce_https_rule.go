package appservice

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/appservice"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU028",
		BadExample: []string{`
 resource "azurerm_function_app" "bad_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
 }
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only",
			"https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
			"https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_function_app"},
		Base:           appservice.CheckEnforceHttps,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.MissingChild("https_only") {
				results.Add("Resource should have https_only set to true, the default is false.", resourceBlock)
				return
			}
			if httpsOnlyAttr := resourceBlock.GetAttribute("https_only"); httpsOnlyAttr.IsFalse() {
				results.Add("Resource should be HTTPS only.", httpsOnlyAttr)
			}
			return results
		},
	})
}
