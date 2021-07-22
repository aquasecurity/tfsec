package sql

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "sql",
		ShortCode: "pg-no-min-statement-logging",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that logging of long statements is disabled.",
			Explanation: `Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.`,
			Impact:      "Sensitive data could be exposed in the database logs.",
			Resolution:  "Disable minimum duration statement logging completely",
			BadExample: `
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
			`,
			GoodExample: `
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
			`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr != nil && dbVersionAttr.IsString() && !dbVersionAttr.StartsWith("POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock == nil {
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr != nil && nameAttr.IsString() && nameAttr.Equals("log_min_duration_statement") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr != nil && valueAttr.IsString() {
						if valueAttr.Value().AsString() != "-1" {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' causes database query statements to be logged", resourceBlock.FullName())),
							)
						}
					}
				}
			}

		},
	})
}
