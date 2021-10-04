package functionapp

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
		Service:   "functionapp",
		ShortCode: "enable-http2",
		Documentation: rule.RuleDocumentation{
			Summary:     "Web App uses the latest HTTP version",
			Explanation: `Use the latest version of HTTP to ensure you are benefiting from security fixes`,
			Impact:      "Outdated versions of HTTP has security vulnerabilities",
			Resolution:  "Use the latest version of HTTP",
			BadExample: []string{`
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
`,
				`
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  site_config {
	  http2_enabled = false
  }
}
`},
			GoodExample: []string{`
resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  site_config {
	  http2_enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#http2_enabled",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_function_app",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if http2EnabledAttr := resourceBlock.GetBlock("site_config").GetAttribute("http2_enabled"); http2EnabledAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for site_config.http2_enabled", resourceBlock.FullName())
			} else if http2EnabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has attribute site_config.http2_enabled that is false", resourceBlock.FullName()).
					WithAttribute(http2EnabledAttr)
			}
		},
	})
}
