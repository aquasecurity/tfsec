package synapse

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
		LegacyID:  "AZU027",
		Service:   "synapse",
		ShortCode: "virtual-network-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:    "Synapse Workspace should have managed virtual network enabled, the default is disabled.",
			Impact:     "Your Synapse workspace is not using the private endpoints",
			Resolution: "Set manage virtual network to enabled",
			Explanation: `
Synapse Workspace does not have managed virtual network enabled by default.

When you create your Azure Synapse workspace, you can choose to associate it to a Microsoft Azure Virtual Network. The Virtual Network associated with your workspace is managed by Azure Synapse. This Virtual Network is called a Managed workspace Virtual Network.
Managed private endpoints are private endpoints created in a Managed Virtual Network associated with your Azure Synapse workspace. Managed private endpoints establish a private link to Azure resources. You can only use private links in a workspace that has a Managed workspace Virtual Network.
`,
			BadExample: []string{`
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
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace#managed_virtual_network_enabled",
				"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints",
				"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_synapse_workspace"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("managed_virtual_network_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' should have managed_virtual_network_enabled set to true, the default is false.", resourceBlock.FullName())
				return
			}
			managedNetworkAttr := resourceBlock.GetAttribute("managed_virtual_network_enabled")
			if managedNetworkAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' should have managed_virtual_network_enabled set to true, the default is false.", resourceBlock.FullName()).
					WithAttribute(managedNetworkAttr)
			}
		},
	})
}
