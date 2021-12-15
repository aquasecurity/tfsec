package sql

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

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
							results.Add("Resource has local file read access enabled.", valueAttr)
						}
					}
				}
			}
			return results
		},
	})
}
