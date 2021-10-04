package database

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
		Service:   "database",
		ShortCode: "no-public-access",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure databases are not publicly accessible",
			Explanation: `Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.`,
			Impact:      "Publicly accessible database could lead to compromised data",
			Resolution:  "Disable public access to database when not required",
			BadExample: []string{`
resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`},
			GoodExample: []string{`
resource "azurerm_postgresql_server" "good_example" {
  name                = "bad_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_mariadb_server", "azurerm_mssql_server", "azurerm_mysql_server", "azurerm_postgresql_server"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("public_network_access_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' has default public network access of enabled", resourceBlock.FullName())
				return
			}

			publicAccessAttr := resourceBlock.GetAttribute("public_network_access_enabled")
			if publicAccessAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' has public access explicitly enabled", resourceBlock.FullName()).
					WithAttribute(publicAccessAttr)
			}
		},
	})
}
