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
		ShortCode: "dotnet-framework-version",
		Documentation: rule.RuleDocumentation{
			Summary:     "Azure App Service Web app does not use the latest .Net Core version",
			Explanation: `Azure App Service web applications developed with the .NET software stack should use the latest available version of .NET to ensure the latest security fixes are in use.`,
			Impact:      "Outdated .NET could contain open vulnerabilities",
			Resolution:  "Use the latest version of the .NET framework",
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
	dotnet_framework_version = "v4.0"
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
	dotnet_framework_version = "v5.0"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#dotnet_framework_version",
				"https://docs.microsoft.com/en-us/azure/app-service/configure-language-dotnetcore",
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
				set.AddResult().
					WithDescription("Resource '%s' does not have a value for site_config block", resourceBlock.FullName())
			}
			siteConfig := resourceBlock.GetBlock("site_config")
			if siteConfig.MissingChild("dotnet_framework_version") {
				set.AddResult().
					WithDescription("Resource '%s' does not have a value for site_config.dotnet_framework_version", resourceBlock.FullName())
			}

			dotNetFramework := siteConfig.GetAttribute("dotnet_framework_version")

			if dotNetFramework.NotEqual("v5.0") || dotNetFramework.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' is configured with incorrect values", resourceBlock.FullName()).
					WithAttribute(dotNetFramework)
			}
		},
	})
}
