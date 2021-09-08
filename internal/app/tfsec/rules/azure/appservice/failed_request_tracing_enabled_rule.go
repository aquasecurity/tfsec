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
		ShortCode: "failed-request-tracing-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "App service does not enable failed request tracing",
			Explanation: `Detailed tracing information on failed requests, including a trace of the IIS components used to process the request and the time taken in each component. It's useful if you want to improve site performance or isolate a specific HTTP error. One folder is generated for each failed request, which contains the XML log file, and the XSL stylesheet to view the log file with.`,
			Impact:      "Logging of failed request tracing will not be logged",
			Resolution:  "Enable failed_request_tracing_enabled",
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

  logs {
    failed_request_tracing_enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#failed_request_tracing_enabled",
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
			if logProps.MissingChild("failed_request_tracing_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.failed_request_tracing_enabled block", resourceBlock.FullName()).WithBlock(logProps)
				return
			}
			failedTracing := logProps.GetAttribute("failed_request_tracing_enabled")
			if failedTracing.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.failed_request_tracing_enabled set to true", resourceBlock.FullName()).
					WithAttribute(failedTracing)
			}
		},
	})
}
