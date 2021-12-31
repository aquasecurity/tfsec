package sql

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 	
 			authorized_networks {
 				value           = "0.0.0.0/0"
 				name            = "internet"
 			}
 		}
 	}
 }
 			`},
		GoodExample: []string{`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 		}
 	}
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_sql_database_instance"},
		Base:           sql.CheckNoPublicAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			ipConfigBlock := resourceBlock.GetBlock("settings").GetBlock("ip_configuration")
			ipv4Attr := ipConfigBlock.GetAttribute("ipv4_enabled")
			if ipv4Attr.IsNil() {
				results.Add("Resource has a public ipv4 address assigned by default", resourceBlock)
				return
			}

			if ipv4Attr.IsTrue() {
				results.Add("Resource has a public ipv4 address explicitly assigned", ipv4Attr)
				return
			}

			for _, authorizedNetworkBlock := range ipConfigBlock.GetBlocks("authorized_networks") {
				if cidrAttr := authorizedNetworkBlock.GetAttribute("value"); cidr.IsAttributeOpen(cidrAttr) {
					results.Add("Resource authorizes access from the public internet", cidrAttr)
				}
			}

			return results
		},
	})
}
