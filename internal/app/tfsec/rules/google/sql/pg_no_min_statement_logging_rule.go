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
 			name  = "log_min_duration_statement"
 			value = "99"
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
 			name  = "log_min_duration_statement"
 			value = "-1"
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckPgNoMinStatementLogging,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr.IsString() && !dbVersionAttr.StartsWith("POSTGRES") {
				return
			}

			for _, dbFlagBlock := range resourceBlock.GetBlock("settings").GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_min_duration_statement") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.NotEqual("-1") {
						results.Add("Resource causes database query statements to be logged", valueAttr)
					}
				}
			}

			return results
		},
	})
}
