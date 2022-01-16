package database

import (
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "azurerm_sql_firewall_rule" "bad_example" {
   name                = "bad_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 
 resource "azurerm_postgresql_firewall_rule" "bad_example" {
   name                = "bad_example"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_postgresql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 `},
		GoodExample: []string{`
 resource "azurerm_sql_firewall_rule" "good_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "0.0.0.0"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address",
		},
		RequiredTypes: []string{"resource"},
		RequiredLabels: []string{
			"azurerm_sql_firewall_rule",
			"azurerm_mysql_firewall_rule",
			"azurerm_postgresql_firewall_rule",
			"azurerm_mariadb_firewall_rule",
		},
		Base: database.CheckNoPublicFirewallAccess,
	})
}
