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
		ShortCode: "pg-log-errors",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that Postgres errors are logged",
			Explanation: `Setting the minimum log severity too high will cause errors not to be logged`,
			Impact:      "Loss of error logging",
			Resolution:  "Set the minimum log severity to at least ERROR",
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
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if !resourceBlock.GetAttribute("database_version").StartsWith("POSTGRES") {
				return
			}

			for _, dbFlagBlock := range resourceBlock.GetBlock("settings").GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_min_messages") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.IsString() {
						switch valueAttr.Value().AsString() {
						case "FATAL", "PANIC", "LOG":
							set.AddResult().
								WithDescription("Resource '%s' has a minimum log severity set which ignores errors", resourceBlock.FullName()).
								WithAttribute(valueAttr)
						}
					}
				}
			}

		},
	})
}
