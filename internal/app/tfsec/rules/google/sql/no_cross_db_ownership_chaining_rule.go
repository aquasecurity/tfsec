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
 		    name  = "cross db ownership chaining"
 		    value = "off"
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckNoCrossDbOwnershipChaining,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			// we only need to check this for SQLSERVER, not mysql/postgres
			if !resourceBlock.GetAttribute("database_version").StartsWith("SQLSERVER") {
				return
			}

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				results.Add("Resource has cross-database ownership chaining enabled by default", resourceBlock)
				return
			}

			for _, dbFlagBlock := range settingsBlock.GetBlocks("database_flags") {
				if dbFlagBlock.GetAttribute("name").Equals("cross db ownership chaining") {
					if valueAttr := dbFlagBlock.GetAttribute("value"); valueAttr.Equals("on") {
						results.Add("Resource has cross-database ownership chaining explicitly enabled", valueAttr)
					}
					// otherwise it's off, awesome
					return
				}
			}

			// we didn't find the flag so it must be on by default
			results.Add("Resource has cross-database ownership chaining enabled by default", resourceBlock)
			return results
		},
	})
}
