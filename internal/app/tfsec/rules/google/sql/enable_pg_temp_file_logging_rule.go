package sql

import (
	"strings"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			dbVersionAttr := resourceBlock.GetAttribute("database_version")
			if dbVersionAttr.IsNotNil() && dbVersionAttr.IsString() && !strings.HasPrefix(dbVersionAttr.Value().AsString(), "POSTGRES") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				results.Add("Resource has temporary file logging disabled by default", ?)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if nameAttr := dbFlagBlock.GetAttribute("name"); nameAttr.IsNotNil() && nameAttr.IsString() && nameAttr.Value().AsString() == "log_temp_files" {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.IsNotNil() && valueAttr.IsString() {
						if valueAttr.Value().AsString() == "-1" {
							results.Add("Resource has temporary file logging explicitly disabled", ?)
						} else if valueAttr.Value().AsString() != "0" {
							results.Add("Resource has temporary file logging disabled for files of certain sizes", ?)
						}
						// otherwise it's off, awesome
						return
					}
				}
			}

			// we didn't find the flag so it must be on by default
			results.Add("Resource has temporary file logging disabled by default", ?)
			return results
		},
	})
}
