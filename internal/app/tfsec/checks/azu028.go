package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUFunctionAppHTTPS scanner.RuleCode = "AZU028"
const AZUFunctionAppHTTPSDescription scanner.RuleSummary = "Ensure the Function App can only be accessed via HTTPS. The default is false."
const AZUFunctionAppHTTPSImpact = "Anyone can access the Function App using HTTP."
const AZUFunctionAppHTTPSResolution = "You can redirect all HTTP requests to the HTTPS port."
const AZUFunctionAppHTTPSExplanation = `
By default, clients can connect to function endpoints by using both HTTP or HTTPS. You should redirect HTTP to HTTPs because HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.
`
const AZUFunctionAppHTTPSBadExample = `
resource "azurerm_function_app" "bad_example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  os_type                    = "linux"
}
`
const AZUFunctionAppHTTPSGoodExample = `
resource "azurerm_function_app" "good_example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  os_type                    = "linux"
  https_only                 = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUFunctionAppHTTPS,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUFunctionAppHTTPSDescription,
			Explanation: AZUFunctionAppHTTPSExplanation,
			Impact:      AZUFunctionAppHTTPSImpact,
			Resolution:  AZUFunctionAppHTTPSResolution,
			BadExample:  AZUFunctionAppHTTPSBadExample,
			GoodExample: AZUFunctionAppHTTPSGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only",
				"https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
				"https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_function_app"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("https_only") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have https_only set to true, the default is false.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			httpsonly := block.GetAttribute("https_only")
			if httpsonly.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' should have https_only set to true, the default is false.", block.FullName()),
						httpsonly.Range(),
						httpsonly,
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
