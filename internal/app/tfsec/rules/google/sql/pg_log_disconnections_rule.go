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
		ShortCode: "pg-log-disconnections",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that logging of disconnections is enabled.",
			Explanation: `Logging disconnections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
			Impact:      "Insufficient diagnostic data.",
			Resolution:  "Enable disconnection logging.",
			BadExample: []string{`
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "log_disconnections"
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
			name  = "log_disconnections"
			value = "on"
		}
	}
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-DISCONNECTIONS",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if !resourceBlock.GetAttribute("database_version").StartsWith("POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' is not configured to log disconnections", resourceBlock.FullName())
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("log_disconnections") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.Equals("off") {
						set.AddResult().
							WithDescription("Resource '%s' is configured not to log disconnections", resourceBlock.FullName()).
							WithAttribute(valueAttr)
					}
					return
				}
			}

			set.AddResult().
				WithDescription("Resource '%s' is not configured to log disconnections", resourceBlock.FullName()).
				WithBlock(settingsBlock)

		},
	})
}
