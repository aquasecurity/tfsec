package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUDataFactoryPublicNetwork = "AZU025"
const AZUDataFactoryPublicNetworkDescription = "Data Factory should have public access disabled, the default is enabled."
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUDataFactoryPublicNetwork,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_data_factory"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("public_network_enabled") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have public_network_enabled set to false, the default is true.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}
			if resourceBlock.GetAttribute("public_network_enabled").IsTrue() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should not have public network set to true.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
