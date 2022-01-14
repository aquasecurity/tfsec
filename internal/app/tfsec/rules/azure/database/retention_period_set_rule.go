package database

import (
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU019",
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_sql_server", "azurerm_sql_server", "azurerm_mssql_database_extended_auditing_policy"},
		Base:           database.CheckRetentionPeriodSet,
	})
}
