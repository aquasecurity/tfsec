package sql

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 }
 			`},
		GoodExample: []string{`
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
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
			"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckNoContainedDbAuth,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			// we only need to check this for SQLSERVER, not mysql/postgres
			if !resourceBlock.GetAttribute("database_version").StartsWith("SQLSERVER") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				results.Add("Resource has contained database authentication enabled by default", resourceBlock)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("contained database authentication") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.Equals("on") {
						results.Add("Resource has contained database authentication explicitly enabled", valueAttr)
					}
					// otherwise it's off, awesome
					return
				}
			}

			// we didn't find the flag so it must be on by default
			results.Add("Resource has contained database authentication enabled by default", resourceBlock)
			return results
		},
	})
}
