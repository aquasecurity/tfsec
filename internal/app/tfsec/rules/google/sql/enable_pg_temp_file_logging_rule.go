package sql

// generator-locked
import (
	"strings"

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
		ShortCode: "enable-pg-temp-file-logging",
		Documentation: rule.RuleDocumentation{
			Summary:     "Temporary file logging should be enabled for all temporary files.",
			Explanation: "Temporary files are not logged by default. To log all temporary files, a value of `0` should set in the `log_temp_files` flag - as all files greater in size than the number of bytes set in this flag will be logged.",
			Impact:      "Use of temporary files will not be logged",
			Resolution:  "Enable temporary file logging for all files",
			BadExample: []string{`
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
}
			`},
			GoodExample: []string{`
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
	    database_flags {
		    name  = "log_temp_files"
		    value = "0"
		}
	}
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://postgresqlco.nf/doc/en/param/log_temp_files/",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr.IsNotNil() && dbVersionAttr.IsString() && !strings.HasPrefix(dbVersionAttr.Value().AsString(), "POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' has temporary file logging disabled by default", resourceBlock.FullName())
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr.IsNotNil() && nameAttr.IsString() && nameAttr.Value().AsString() == "log_temp_files" {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.IsNotNil() && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "-1" {
							set.AddResult().
								WithDescription("Resource '%s' has temporary file logging explicitly disabled", resourceBlock.FullName())
						} else if valueAttr.Value().AsString() != "0" {
							set.AddResult().
								WithDescription("Resource '%s' has temporary file logging disabled for files of certain sizes", resourceBlock.FullName())
						}
						// otherwise it's off, awesome
						return
					}
				}
			}

			// we didn't find the flag so it must be on by default
			set.AddResult().
				WithDescription("Resource '%s' has temporary file logging disabled by default", resourceBlock.FullName())

		},
	})
}
