package database

import (
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "azurerm_sql_server" "example" {
   name                         = "mysqlserver"
 }

 resource "azurerm_mssql_server_security_alert_policy" "bad_example" {
   resource_group_name        = azurerm_resource_group.example.name
   server_name                = azurerm_sql_server.example.name
   state                      = "Enabled"
   storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   disabled_alerts = [
     "Sql_Injection",
     "Data_Exfiltration"
   ]
   email_addresses = []
 }
 `},
		GoodExample: []string{`
 resource "azurerm_sql_server" "example" {
	name                         = "mysqlserver"
 }

 resource "azurerm_mssql_server_security_alert_policy" "good_example" {
   resource_group_name        = azurerm_resource_group.example.name
   server_name                = azurerm_sql_server.example.name
   state                      = "Enabled"
   storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   disabled_alerts = [
     "Sql_Injection",
     "Data_Exfiltration"
   ]
   email_addresses = ["db-security@acme.org"]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_mssql_server_security_alert_policy",
		},
		Base: database.CheckThreatAlertEmailSet,
	})
}
