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
		ShortCode: "python-version",
		Documentation: rule.RuleDocumentation{
			Summary:     "Azure App Service Web app does not use the latest Python version",
			Explanation: `Azure App Service web applications developed with the Python should use the latest available version of Python to ensure the latest security fixes are in use.`,
			Impact:      "Old Python Versions can contain vulnerabilities which lead to compromised Web Applications",
			Resolution:  "Ensure Latest Python Version is being used",
			BadExample: []string{`
resource "azurerm_app_service" "good_example" {
	name                = "example-app-service"
	location            = azurerm_resource_group.example.location
	resource_group_name = azurerm_resource_group.example.name
	app_service_plan_id = azurerm_app_service_plan.example.id
	site_config {
	  python_version = "2.7"
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
    python_version = "3.4"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version",
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
			if resourceBlock.MissingChild("site_config") {
				return
			}
			// We are only running this check if the python_version tag is set, if the app service is not using python we should not count this against them
			if resourceBlock.GetBlock("site_config").HasBlock("python_version") {
				if pythonVersionAttr := resourceBlock.GetBlock("site_config").GetAttribute("python_version"); pythonVersionAttr.NotEqual("3.4") {
					set.AddResult().
						WithDescription("Resource '%s' does not have site_config.python_version set to 3.4 which is the latest version", resourceBlock.FullName()).
						WithAttribute(pythonVersionAttr)
				} else {
					return
				}
			} else {
				return
			}

		},
	})
}
