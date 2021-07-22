package sql

import (
	"fmt"
	"strings"

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
		ShortCode: "pg-log-checkpoints",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that logging of checkpoints is enabled.",
			Explanation: `Logging checkpoints provides useful diagnostic data, which can identify performance issues in an application and potential DoS vectors.`,
			Impact:      "Insufficient diagnostic data.",
			Resolution:  "Enable checkpoints logging.",
			BadExample: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "log_checkpoints"
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
			name  = "log_checkpoints"
			value = "on"
		}
	}
}
			`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CHECKPOINTS",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr != nil && dbVersionAttr.IsString() && !strings.HasPrefix(dbVersionAttr.Value().AsString(), "POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is not configured to log checkpoints", resourceBlock.FullName())),
				)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr != nil && nameAttr.IsString() && nameAttr.Value().AsString() == "log_checkpoints" {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr != nil && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "off" {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' is configured not to log checkpoints", resourceBlock.FullName())),
							)
						}
						return
					}
				}
			}

			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' is not configured to log checkpoints", resourceBlock.FullName())),
			)

		},
	})
}
