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
 `,
			`
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
   site_config {
 	  http2_enabled = false
   }
 }
 `},
		GoodExample: []string{`
 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   site_config {
 	  http2_enabled = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		Base: appservice.CheckEnableHttp2,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if configBlock := resourceBlock.GetBlock("site_config"); configBlock.IsNil() {
				results.Add("Resource uses default value for site_config.http2_enabled", resourceBlock)
			} else if http2EnabledAttr := configBlock.GetAttribute("http2_enabled"); http2EnabledAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for site_config.http2_enabled", configBlock)
			} else if http2EnabledAttr.IsFalse() {
				results.Add("Resource has attribute site_config.http2_enabled that is false", http2EnabledAttr)
			}
			return results
		},
	})
}
