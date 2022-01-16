package database

import (
	"github.com/aquasecurity/defsec/rules/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "azurerm_postgresql_server" "bad_example" {
   name                = "bad_example"
 
   public_network_access_enabled    = true
   ssl_enforcement_enabled          = false
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }
 `},
		GoodExample: []string{`
 resource "azurerm_postgresql_server" "good_example" {
   name                = "bad_example"
 
   public_network_access_enabled    = false
   ssl_enforcement_enabled          = false
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled",
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled",
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_mariadb_server", "azurerm_mssql_server", "azurerm_mysql_server", "azurerm_postgresql_server"},
		Base:           database.CheckNoPublicAccess,
	})
}
