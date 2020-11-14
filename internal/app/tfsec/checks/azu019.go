package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUDatabaseAuditingRetention90Days scanner.RuleCode = "AZU019"
const AZUDatabaseAuditingRetention90DaysDescription scanner.RuleSummary = "Database auditing rentention period should be longer than 90 days"
const AZUDatabaseAuditingRetention90DaysExplanation = `
When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.

If the retention period is to be explicitly set, it should be set for no less than 90 days.

`
const AZUDatabaseAuditingRetention90DaysBadExample = `
resource "azurerm_mssql_database_extended_auditing_policy" "bad_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 6
}
`
const AZUDatabaseAuditingRetention90DaysGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUDatabaseAuditingRetention90Days,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUDatabaseAuditingRetention90DaysDescription,
			Explanation: AZUDatabaseAuditingRetention90DaysExplanation,
			BadExample:  AZUDatabaseAuditingRetention90DaysBadExample,
			GoodExample: AZUDatabaseAuditingRetention90DaysGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days",
				"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_sql_server", "azurerm_sql_server", "azurerm_mssql_database_extended_auditing_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if !block.IsResourceType("azurerm_mssql_database_extended_auditing_policy") {
				if block.MissingChild("extended_auditing_policy") {
					return nil
				}
				block = block.GetBlock("extended_auditing_policy")
			}

			if block.MissingChild("retention_in_days") {
				// using default of unlimited
				return nil
			}
			if block.GetAttribute("retention_in_days").LessThan(90) {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' specifies a retention period of less than 90 days.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
