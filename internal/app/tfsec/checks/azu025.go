package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUDataFactoryPublicNetwork scanner.RuleCode = "AZU025"
const AZUDataFactoryPublicNetworkDescription scanner.RuleSummary = "Data Factory should have public access disabled, the default is enabled."
const AZUDataFactoryPublicNetworkImpact = "Data factory is publicly accessible"
const AZUDataFactoryPublicNetworkResolution = "Set public access to disabled for Data Factory"
const AZUDataFactoryPublicNetworkExplanation = `
Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.
`
const AZUDataFactoryPublicNetworkBadExample = `
resource "azurerm_data_factory" "bad_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}
`
const AZUDataFactoryPublicNetworkGoodExample = `
resource "azurerm_data_factory" "good_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  public_network_enabled = false
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUDataFactoryPublicNetwork,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUDataFactoryPublicNetworkDescription,
			Impact:      AZUDataFactoryPublicNetworkImpact,
			Resolution:  AZUDataFactoryPublicNetworkResolution,
			Explanation: AZUDataFactoryPublicNetworkExplanation,
			BadExample:  AZUDataFactoryPublicNetworkBadExample,
			GoodExample: AZUDataFactoryPublicNetworkGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled",
				"https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_factory"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("public_network_enabled") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have public_network_enabled set to false, the default is true.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			if block.GetAttribute("public_network_enabled").IsTrue() || block.GetAttribute("public_network_enabled").Equals("true") || block.GetAttribute("public_network_enabled").Equals(true) {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should not have public network set to true.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
