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
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "PANIC"
 		}
 	}
 }
 			`},
		GoodExample: []string{`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "WARNING"
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
			"https://postgresqlco.nf/doc/en/param/log_min_messages/",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckPgLogErrors,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if !resourceBlock.GetAttribute("database_version").StartsWith("POSTGRES") {
				return
			}

			for _, dbFlagBlock := range resourceBlock.GetBlock("settings").GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_min_messages") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.IsString() {
						switch valueAttr.Value().AsString() {
						case "FATAL", "PANIC", "LOG":
							results.Add("Resource has a minimum log severity set which ignores errors", valueAttr)
						}
					}
				}
			}

			return results
		},
	})
}
