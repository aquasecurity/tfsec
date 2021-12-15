package sql

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr.IsString() && !dbVersionAttr.StartsWith("POSTGRES") {
				return
			}

			for _, dbFlagBlock := range resourceBlock.GetBlock("settings").GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_min_duration_statement") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.NotEqual("-1") {
						results.Add("Resource causes database query statements to be logged", ?)
					}
				}
			}

			return results
		},
	})
}
