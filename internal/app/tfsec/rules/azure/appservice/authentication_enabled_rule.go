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
		BadExample: []string{`
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 `},
		GoodExample: []string{`
 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   auth_settings {
     enabled = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#enabled",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		Base: appservice.CheckAuthenticationEnabled,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if authBlock := resourceBlock.GetBlock("auth_settings"); authBlock.IsNil() {
				results.Add("Resource uses default value for auth_settings.enabled", resourceBlock)
			} else if enabledAttr := authBlock.GetAttribute("enabled"); enabledAttr.IsNil() {
				results.Add("Resource uses default value for auth_settings.enabled", authBlock)
			} else if enabledAttr.IsFalse() {
				results.Add("Resource has attribute auth_settings.enabled that is false", enabledAttr)
			}
			return results
		},
	})
}
