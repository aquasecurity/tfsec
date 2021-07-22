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
		ShortCode: "no-cross-db-ownership-chaining",
		Documentation: rule.RuleDocumentation{
			Summary:     "Cross-database ownership chaining should be disabled",
			Explanation: `Cross-database ownership chaining, also known as cross-database chaining, is a security feature of SQL Server that allows users of databases access to other databases besides the one they are currently using.`,
			Impact:      "Unintended access to sensitive data",
			Resolution:  "Disable cross database ownership chaining",
			BadExample: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "SQLSERVER_2017_STANDARD"
	region           = "us-central1"
}
			`,
			GoodExample: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "SQLSERVER_2017_STANDARD"
	region           = "us-central1"
	settings {
	    database_flags {
		    name  = "cross db ownership chaining"
		    value = "off"
		}
	}
}
			`,
			Links: []string{"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15"},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			// we only need to check this for SQLSERVER, not mysql/postgres
			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr == nil || !dbVersionAttr.IsString() {
				// default is postgres
				return
			}

			if !strings.HasPrefix(dbVersionAttr.Value().AsString(), "SQLSERVER") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has cross-database ownership chaining enabled by default", resourceBlock.FullName())),
				)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr != nil && nameAttr.IsString() && nameAttr.Value().AsString() == "cross db ownership chaining" {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr != nil && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "on" {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' has cross-database ownership chaining explicitly enabled", resourceBlock.FullName())),
							)
						}
						// otherwise it's off, awesome
						return
					}
				}
			}

			// we didn't find the flag so it must be on by default
			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' has cross-database ownership chaining enabled by default", resourceBlock.FullName())),
			)

		},
	})
}
