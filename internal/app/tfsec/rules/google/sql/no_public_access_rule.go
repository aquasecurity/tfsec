package sql

import (
	"github.com/aquasecurity/defsec/rules/google/sql"
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
 	
 			authorized_networks {
 				value           = "0.0.0.0/0"
 				name            = "internet"
 			}
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
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckNoPublicAccess,
	})
}
