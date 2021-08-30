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
		ShortCode: "authentication-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "Function App authentication is activated",
			Explanation: `Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings`,
			Impact:      "Anonymous HTTP requests will be accepted",
			Resolution:  "Enable authentication to prevent anonymous request being accepted",
			BadExample: []string{`
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id
}
`},
			GoodExample: []string{`
resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#enabled",
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
			if enabledAttr := resourceBlock.GetBlock("auth_settings").GetAttribute("enabled"); enabledAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for auth_settings.enabled", resourceBlock.FullName())
			} else if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has attribute auth_settings.enabled that is false", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}
		},
	})
}
