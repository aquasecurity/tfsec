package database

import (
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU018",
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_sql_server", "azurerm_mssql_server"},
		Base:           database.CheckEnableAudit,
	})
}
