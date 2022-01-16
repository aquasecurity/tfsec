package sql

import (
	"github.com/aquasecurity/defsec/rules/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "on"
 		}
 	}
 }
 			`},
		GoodExample: []string{`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "off"
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
			"https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html"},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckMysqlNoLocalInfile,
	})
}
