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
		ShortCode: "php-version",
		Documentation: rule.RuleDocumentation{
			Summary:     "Azure App Service Web app does not use the latest PHP version",
			Explanation: `Azure App Service web applications developed with the PHP should use the latest available version of PHP to ensure the latest security fixes are in use.`,
			Impact:      "Old PHP Versions can contain vulnerabilities which lead to compromised Web Applications",
			Resolution:  "Ensure Latest PHP Version is being used",
			BadExample: []string{`
resource "azurerm_app_service" "good_example" {
	name                = "example-app-service"
	location            = azurerm_resource_group.example.location
	resource_group_name = azurerm_resource_group.example.name
	app_service_plan_id = azurerm_app_service_plan.example.id
	site_config {
	  php_version = "7.3"
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
    php_version = "7.4"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#php_version",
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
			// We are only running this check if the php_version tag is set, if the app service is not using php we should not count this against them
			if resourceBlock.GetBlock("site_config").HasBlock("php_version") {
				if phpVersionAttr := resourceBlock.GetBlock("site_config").GetAttribute("php_version"); phpVersionAttr.NotEqual("7.4") {
					set.AddResult().
						WithDescription("Resource '%s' does not have site_config.php_version set to 7.4 which is the latest version", resourceBlock.FullName()).
						WithAttribute(phpVersionAttr)
				} else {
					return
				}
			} else {
				return
			}

		},
	})
}
