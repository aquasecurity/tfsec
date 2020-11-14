package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUSQLDatabaseAuditingEnabled scanner.RuleCode = "AZU018"
const AZUSQLDatabaseAuditingEnabledDescription scanner.RuleSummary = "Auditing should be enabled on Azure SQL Databases"
const AZUSQLDatabaseAuditingEnabledExplanation = `
Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.
`
const AZUSQLDatabaseAuditingEnabledBadExample = `
resource "azurerm_sql_server" "bad_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"
}
`
const AZUSQLDatabaseAuditingEnabledGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUSQLDatabaseAuditingEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUSQLDatabaseAuditingEnabledDescription,
			Explanation: AZUSQLDatabaseAuditingEnabledExplanation,
			BadExample:  AZUSQLDatabaseAuditingEnabledBadExample,
			GoodExample: AZUSQLDatabaseAuditingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server#extended_auditing_policy",
				"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_sql_server", "azurerm_mssql_server"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("extended_auditing_policy") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have extended audit configured.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
