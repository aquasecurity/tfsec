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
		ShortCode: "encrypt-in-transit-data",
		Documentation: rule.RuleDocumentation{
			Summary:     "SSL connections to a SQL database instance should be enforced.",
			Explanation: `In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.`,
			Impact:      "Intercepted data can be read in transit",
			Resolution:  "Enforce SSL for all connections",
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
			require_ssl = false
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
			require_ssl = true
		}
	}
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance",
				"https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_sql_database_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			settingsBlock := resourceBlock.GetBlock("settings")
			if settingsBlock.IsNil() {
				return
			}

			ipConfigBlock := settingsBlock.GetBlock("ip_configuration")
			if ipConfigBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not require SSL for all connections", resourceBlock.FullName())
				return
			}

			if requireSSLAttr := ipConfigBlock.GetAttribute("require_ssl"); requireSSLAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not require SSL for all connections", resourceBlock.FullName())
			} else if requireSSLAttr.IsFalse() {
				set.AddResult().
					WithAttribute(requireSSLAttr).
					WithDescription("Resource '%s' explicitly does not require SSL for all connections", resourceBlock.FullName())
			}

		},
	})
}
