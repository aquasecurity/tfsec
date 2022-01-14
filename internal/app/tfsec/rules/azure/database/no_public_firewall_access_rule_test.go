package database

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureNoPublicFirewallAccess(t *testing.T) {
	expectedCode := "azure-database-no-public-firewall-access"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "rule with open ip range fails check",
			source: `
 resource "azurerm_mssql_server" "example" {
	name                         = "myserver"
 }

 resource "azurerm_sql_firewall_rule" "bad_example" {
   name                = "bad_example"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_mssql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "postgresql rule with open ip range fails check",
			source: `
resource "azurerm_postgresql_server" "example" {
	name                         = "myserver"
}
			
 resource "azurerm_postgresql_firewall_rule" "bad_example" {
   name                = "bad_example"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_postgresql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule with public start and end ip fails check",
			source: `
 resource "azurerm_sql_server" "example" {
	name                         = "mysqlserver"
 }
				
 resource "azurerm_sql_firewall_rule" "bad_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "0.0.0.0"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule with specific Azure services start and end ip passes check",
			source: `
 resource "azurerm_sql_server" "example" {
	name                         = "mysqlserver"
 }

 resource "azurerm_postgresql_server" "example" {
	name                         = "myserver"
 }
 
 resource "azurerm_sql_firewall_rule" "good_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "10.0.2.0"
   end_ip_address      = "10.0.2.240"
 }
 
 resource "azurerm_postgresql_firewall_rule" "good_example" {
 	name                = "good_rule"
 	resource_group_name = azurerm_resource_group.example.name
 	server_name         = azurerm_postgresql_server.example.name
 	start_ip_address    = "10.0.2.0"
 	end_ip_address      = "10.0.2.240"
   }
 `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
