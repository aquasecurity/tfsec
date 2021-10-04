package database

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
		LegacyID:  "AZU019",
		Service:   "database",
		ShortCode: "retention-period-set",
		Documentation: rule.RuleDocumentation{
			Summary:    "Database auditing rentention period should be longer than 90 days",
			Impact:     "Short logging retention could result in missing valuable historical information",
			Resolution: "Set retention periods of database auditing to greater than 90 days",
			Explanation: `
When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.

If the retention period is to be explicitly set, it should be set for no less than 90 days.

`,
			BadExample: []string{`
resource "azurerm_mssql_database_extended_auditing_policy" "bad_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 6
}
`},
			GoodExample: []string{`
resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
}

resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days",
				"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_sql_server", "azurerm_sql_server", "azurerm_mssql_database_extended_auditing_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if !resourceBlock.IsResourceType("azurerm_mssql_database_extended_auditing_policy") {
				if resourceBlock.MissingChild("extended_auditing_policy") {
					return
				}
				resourceBlock = resourceBlock.GetBlock("extended_auditing_policy")
			}

			if resourceBlock.MissingChild("retention_in_days") {
				// using default of unlimited
				return
			}
			if resourceBlock.GetAttribute("retention_in_days").LessThan(90) {
				set.AddResult().
					WithDescription("Resource '%s' specifies a retention period of less than 90 days.", resourceBlock.FullName())
			}

		},
	})
}
