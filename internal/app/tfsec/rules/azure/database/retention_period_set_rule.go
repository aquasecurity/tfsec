package database

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_sql_server", "azurerm_sql_server", "azurerm_mssql_database_extended_auditing_policy"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
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
				results.Add("Resource specifies a retention period of less than 90 days.", resourceBlock)
			}

			return results
		},
	})
}
