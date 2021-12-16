package database

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/firewall-rules/create-or-update",
		},
		RequiredTypes: []string{"resource"},
		RequiredLabels: []string{
			"azurerm_sql_firewall_rule",
			"azurerm_mysql_firewall_rule",
			"azurerm_postgresql_firewall_rule",
			"azurerm_mariadb_firewall_rule",
		},
		Base: database.CheckNoPublicFirewallAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("start_ip_address") || resourceBlock.MissingChild("end_ip_address") {
				return
			}

			sourceIpAttr := resourceBlock.GetAttribute("start_ip_address")
			endIpAttr := resourceBlock.GetAttribute("end_ip_address")
			if sourceIpAttr.Equals("0.0.0.0") && endIpAttr.NotEqual("0.0.0.0") {
				results.Add("Resource has an open IP range set.", sourceIpAttr)
			}

			return results
		},
	})
}
