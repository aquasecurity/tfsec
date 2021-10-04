package database

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU018",
		Service:   "database",
		ShortCode: "enable-audit",
		Documentation: rule.RuleDocumentation{
			Summary:    "Auditing should be enabled on Azure SQL Databases",
			Impact:     "Auditing provides valuable information about access and usage",
			Resolution: "Enable auditing on Azure SQL databases",
			Explanation: `
Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.
`,
			BadExample: []string{`
resource "azurerm_sql_server" "bad_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"
}
`},
			GoodExample: []string{`
resource "azurerm_sql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server#extended_auditing_policy",
				"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_sql_server", "azurerm_mssql_server"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			if resourceBlock.HasChild("extended_auditing_policy") {
				return
			}

			blocks, err := module.GetReferencingResources(resourceBlock, "azurerm_mssql_server_extended_auditing_policy", "server_id")
			if err != nil {
				debug.Log("Failed to locate referencing blocks for %s", resourceBlock.FullName())
				return
			}

			if len(blocks) > 0 {
				return
			}

			set.AddResult().
				WithDescription("Resource '%s' does not have an extended audit policy configured.", resourceBlock.FullName())

		},
	})
}
