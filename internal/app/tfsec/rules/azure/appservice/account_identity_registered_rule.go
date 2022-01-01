package appservice

import (
	"github.com/aquasecurity/defsec/rules/azure/appservice"
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
 
   identity {
     type = "UserAssigned"
     identity_ids = "webapp1"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		Base: appservice.CheckAccountIdentityRegistered,
	})
}
