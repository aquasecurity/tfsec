package sql

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckEncryptInTransitData,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				return
			}

			ipConfigBlock := settingsBlock.GetBlock("ip_configuration")
			if ipConfigBlock.IsNil() {
				results.Add("Resource does not require SSL for all connections", settingsBlock)
				return
			}

			if requireSSLAttr := ipConfigBlock.GetAttribute("require_ssl"); requireSSLAttr.IsNil() {
				results.Add("Resource does not require SSL for all connections", ipConfigBlock)
			} else if requireSSLAttr.IsFalse() {
				results.Add("Resource explicitly does not require SSL for all connections", requireSSLAttr)
			}

			return results
		},
	})
}
