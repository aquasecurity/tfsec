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
		ShortCode: "pg-log-lock-waits",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that logging of lock waits is enabled.",
			Explanation: `Lock waits are often an indication of poor performance and often an indicator of a potential denial of service vulnerability, therefore occurrences should be logged for analysis.`,
			Impact:      "Issues leading to denial of service may not be identified.",
			Resolution:  "Enable lock wait logging.",
			BadExample: `
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
			`,
			GoodExample: `
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
			`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr != nil && dbVersionAttr.IsString() && !dbVersionAttr.StartsWith("POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is not configured to log lock waits", resourceBlock.FullName())),
				)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr != nil && nameAttr.IsString() && nameAttr.Equals("log_lock_waits") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr != nil && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "off" {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' is configured not to log lock waits", resourceBlock.FullName())),
							)
						}
						return
					}
				}
			}

			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' is not configured to log lock waits", resourceBlock.FullName())),
			)

		},
	})
}
