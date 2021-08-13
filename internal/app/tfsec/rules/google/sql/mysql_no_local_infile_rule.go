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
		ShortCode: "mysql-no-local-infile",
		Documentation: rule.RuleDocumentation{
			Summary:     "Disable local_infile setting in MySQL",
			Explanation: `Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.`,
			Impact:      "Arbitrary files read by attackers when combined with a SQL injection vulnerability.",
			Resolution:  "Disable the local infile setting",
			BadExample: []string{`
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "MYSQL_5_6"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "local_infile"
			value = "on"
		}
	}
}
			`},
			GoodExample: []string{`
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "MYSQL_5_6"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "local_infile"
			value = "off"
		}
	}
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html"},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			// we only need to check this for MYSQL
			if !resourceBlock.GetAttribute("database_version").StartsWith("MYSQL") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr.IsNotNil() && nameAttr.IsString() && nameAttr.Equals("local_infile") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.IsNotNil() && valueAttr.IsString() {
						if valueAttr.Equals("on", block.IgnoreCase) {
							set.AddResult().
								WithDescription("Resource '%s' has local file read access enabled.", resourceBlock.FullName())
						}
					}
				}
			}
		},
	})
}
