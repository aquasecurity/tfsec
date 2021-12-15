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
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = false
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
 		backup_configuration {
 			enabled = true
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true",
			"https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				results.Add("Resource does not have backups enabled.", ?)
				return
			}

			if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNil() {
				results.Add("Resource does not have backups enabled.", ?)
			} else if enabledAttr := backupBlock.GetAttribute("enabled"); enabledAttr.IsNil() {
				results.Add("Resource does not have backups enabled.", ?)
			} else if enabledAttr.IsFalse() {
				results.Add("Resource has backups explicitly disabled.", enabledAttr)
			}
			return results
		},
	})
}
