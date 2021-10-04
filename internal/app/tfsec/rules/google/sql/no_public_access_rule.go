package sql

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "sql",
		ShortCode: "no-public-access",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that Cloud SQL Database Instances are not publicly exposed",
			Explanation: `Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.`,
			Impact:      "Public exposure of sensitive data",
			Resolution:  "Remove public access from database instances",
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
				"https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			ipConfigBlock := resourceBlock.GetBlock("settings").GetBlock("ip_configuration")
			ipv4Attr := ipConfigBlock.GetAttribute("ipv4_enabled")
			if ipv4Attr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' has a public ipv4 address assigned by default", resourceBlock.FullName())
				return
			}

			if ipv4Attr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' has a public ipv4 address explicitly assigned", resourceBlock.FullName()).
					WithAttribute(ipv4Attr)
				return
			}

			for _, authorizedNetworkBlock := range ipConfigBlock.GetBlocks("authorized_networks") {
				if cidrAttr := authorizedNetworkBlock.GetAttribute("value"); cidr.IsAttributeOpen(cidrAttr) {
					set.AddResult().
						WithDescription("Resource '%s' authorizes access from the public internet", resourceBlock.FullName()).
						WithAttribute(cidrAttr)
				}
			}

		},
	})
}
