package datafactory

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU025",
		Service:   "datafactory",
		ShortCode: "no-public-access",
		Documentation: rule.RuleDocumentation{
			Summary:    "Data Factory should have public access disabled, the default is enabled.",
			Impact:     "Data factory is publicly accessible",
			Resolution: "Set public access to disabled for Data Factory",
			Explanation: `
Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.
`,
			BadExample: []string{`
resource "azurerm_data_factory" "bad_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}
`},
			GoodExample: []string{`
resource "azurerm_data_factory" "good_example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  public_network_enabled = false
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled",
				"https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_data_factory"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("public_network_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' should have public_network_enabled set to false, the default is true.", resourceBlock.FullName())
				return
			}
			publicAccessAttr := resourceBlock.GetAttribute("public_network_enabled")
			if publicAccessAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' should not have public network set to true.", resourceBlock.FullName())
			}
		},
	})
}
