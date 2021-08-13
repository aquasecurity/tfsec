package sql

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "sql",
		ShortCode: "enable-backup",
		Documentation: rule.RuleDocumentation{
			Summary:     "Enable automated backups to recover from data-loss",
			Explanation: `Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.`,
			Impact:      "No recovery of lost or corrupted data",
			Resolution:  "Enable automated backups",
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
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have backups enabled.", resourceBlock.FullName())
				return
			}

			if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have backups enabled.", resourceBlock.FullName())
			} else if enabledAttr := backupBlock.GetAttribute("enabled"); enabledAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have backups enabled.", resourceBlock.FullName())
			} else if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has backups explicitly disabled.", resourceBlock.FullName())
			}
		},
	})
}
