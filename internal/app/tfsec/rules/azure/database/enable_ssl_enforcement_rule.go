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
		ShortCode: "enable-ssl-enforcement",
		Documentation: rule.RuleDocumentation{
			Summary:     "SSL should be enforced on database connections where applicable",
			Explanation: `SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.`,
			Impact:      "Insecure connections could lead to data loss and other vulnerabilities",
			Resolution:  "Enable SSL enforcement",
			BadExample: []string{`
resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`},
			GoodExample: []string{`
resource "azurerm_postgresql_server" "good_example" {
  name                = "good_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_enforcement_enabled",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_enforcement_enabled",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_mariadb_server", "azurerm_mysql_server", "azurerm_postgresql_server"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("ssl_enforcement_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' is missing the required ssl_enforcement_enabled attribute", resourceBlock.FullName())
				return
			}

			sslEnforceAttr := resourceBlock.GetAttribute("ssl_enforcement_enabled")
			if sslEnforceAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has ssl_enforcement_enabled disabled", resourceBlock.FullName()).
					WithAttribute(sslEnforceAttr)
			}
		},
	})
}
