package appservice

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AzureProvider,
		Service:   "appservice",
		ShortCode: "http-logs-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "App service does not enable HTTP logging",
			Explanation: `Raw HTTP request data in the W3C extended log file format. Each log message includes data such as the HTTP method, resource URI, client IP, client port, user agent, response code, and so on.`,
			Impact:      "Missed logs related to HTTP requests",
			Resolution:  "Enable http_logs",
			BadExample: []string{`
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
`},
			GoodExample: []string{`
resource "azurerm_app_service" "good_example_one" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  logs {
    http_logs {
	  file_system {
		retention_in_days = 4
		retention_in_mb  = 25
	  }
	}
  }
}`,
				`resource "azurerm_app_service" "good_example_two" {
	name                = "example-app-service"
	location            = azurerm_resource_group.example.location
	resource_group_name = azurerm_resource_group.example.name
	app_service_plan_id = azurerm_app_service_plan.example.id
	logs {
	  http_logs {
		azure_blob_storage {
		  level = "Information"
		  sas_url  = "https://someblob.file.core.windows.net/?sv=ABC"
		}
	  }
	}
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http_logs",
				"https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			if resourceBlock.MissingChild("logs") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs enabled", resourceBlock.FullName())
				return
			}
			logProps := resourceBlock.GetBlock("logs")
			if logProps.MissingChild("http_logs") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.http_logs enabled", resourceBlock.FullName()).WithBlock(logProps)
				return
			}
			if logProps.MissingNestedChild("http_logs.file_system") && logProps.MissingNestedChild("http_logs.azure_blob_storage") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.http_logs.file_system or logs.http_logs.azure_blob_storage configured", resourceBlock.FullName()).WithBlock(logProps)
			}
		},
	})
}
