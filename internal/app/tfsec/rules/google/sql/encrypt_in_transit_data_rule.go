package sql

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 			require_ssl = false
 		}
 	}
 }
 			`},
		GoodExample: []string{`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 			require_ssl = true
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
			"https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				return
			}

			ipConfigBlock := settingsBlock.GetBlock("ip_configuration")
			if ipConfigBlock.IsNil() {
				results.Add("Resource does not require SSL for all connections", ?)
				return
			}

			if requireSSLAttr := ipConfigBlock.GetAttribute("require_ssl"); requireSSLAttr.IsNil() {
				results.Add("Resource does not require SSL for all connections", ?)
			} else if requireSSLAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource explicitly does not require SSL for all connections", ?)
			}

			return results
		},
	})
}
