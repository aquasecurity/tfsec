package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUSynapseWorkspaceManagedNetwork scanner.RuleCode = "AZU027"
const AZUSynapseWorkspaceManagedNetworkDescription scanner.RuleSummary = "Synapse Workspace should have managed virtual network enabled, the default is disabled."
const AZUSynapseWorkspaceManagedNetworkExplanation = `
Synapse Workspace does not have managed virtual network enabled by default.

When you create your Azure Synapse workspace, you can choose to associate it to a Microsoft Azure Virtual Network. The Virtual Network associated with your workspace is managed by Azure Synapse. This Virtual Network is called a Managed workspace Virtual Network.
Managed private endpoints are private endpoints created in a Managed Virtual Network associated with your Azure Synapse workspace. Managed private endpoints establish a private link to Azure resources. You can only use private links in a workspace that has a Managed workspace Virtual Network.
`
const AZUSynapseWorkspaceManagedNetworkBadExample = `
resource "azurerm_synapse_workspace" "bad_example" {
  name                                 = "example"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "H@Sh1CoR3!"

  aad_admin {
    login     = "AzureAD Admin"
    object_id = "00000000-0000-0000-0000-000000000000"
    tenant_id = "00000000-0000-0000-0000-000000000000"
  }

  tags = {
    Env = "production"
  }
}
`
const AZUSynapseWorkspaceManagedNetworkGoodExample = `
resource "azurerm_synapse_workspace" "good_example" {
  name                                 = "example"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "H@Sh1CoR3!"
  managed_virtual_network_enabled	   = true
  aad_admin {
    login     = "AzureAD Admin"
    object_id = "00000000-0000-0000-0000-000000000000"
    tenant_id = "00000000-0000-0000-0000-000000000000"
  }

  tags = {
    Env = "production"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUSynapseWorkspaceManagedNetwork,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUSynapseWorkspaceManagedNetworkDescription,
			Explanation: AZUSynapseWorkspaceManagedNetworkExplanation,
			BadExample:  AZUSynapseWorkspaceManagedNetworkBadExample,
			GoodExample: AZUSynapseWorkspaceManagedNetworkGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace#managed_virtual_network_enabled",
				"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints",
				"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_synapse_workspace"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("managed_virtual_network_enabled") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have managed_virtual_network_enabled set to true, the default is false.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			managedNetwork := block.GetAttribute("managed_virtual_network_enabled")
			if managedNetwork.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' should have managed_virtual_network_enabled set to true, the default is false.", block.FullName()),
						managedNetwork.Range(),
						managedNetwork,
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
