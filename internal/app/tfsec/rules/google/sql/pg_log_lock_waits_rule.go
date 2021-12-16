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
 			name  = "log_lock_waits"
 			value = "off"
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
 			name  = "log_lock_waits"
 			value = "on"
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckPgLogLockWaits,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if !resourceBlock.GetAttribute("database_version").StartsWith("POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				results.Add("Resource is not configured to log lock waits", resourceBlock)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_lock_waits") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.Equals("off") {
						results.Add("Resource is configured not to log lock waits", valueAttr)
					}
					return
				}
			}

			results.Add("Resource is not configured to log lock waits", resourceBlock)
			return results
		},
	})
}
