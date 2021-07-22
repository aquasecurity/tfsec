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
		ShortCode: "no-contained-db-auth",
		Documentation: rule.RuleDocumentation{
			Summary:     "Contained database authentication should be disabled",
			Explanation: `Users with ALTER permissions on users can grant access to a contained database without the knowledge of an administrator`,
			Impact:      "Access can be granted without knowledge of the database administrator",
			Resolution:  "Disable contained database authentication",
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
		    name  = "contained database authentication"
		    value = "off"
		}
	}
}
			`,
			Links: []string{"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15"},
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
						WithDescription(fmt.Sprintf("Resource '%s' has contained database authentication enabled by default", resourceBlock.FullName())),
				)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr != nil && nameAttr.IsString() && nameAttr.Value().AsString() == "contained database authentication" {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr != nil && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "on" {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' has contained database authentication explicitly enabled", resourceBlock.FullName())),
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
					WithDescription(fmt.Sprintf("Resource '%s' has contained database authentication enabled by default", resourceBlock.FullName())),
			)
		},
	})
}
