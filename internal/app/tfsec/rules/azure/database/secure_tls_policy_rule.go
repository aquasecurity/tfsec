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
		ShortCode: "secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:     "Databases should have the minimum TLS set for connections",
			Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
			Impact:      "Outdated TLS policies increase exposure to known issues",
			Resolution:  "Use the most modern TLS policies available",
			BadExample: []string{`
resource "azurerm_mssql_server" "bad_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "missadministrator"
  administrator_login_password = "thisIsKat11"
  minimum_tls_version          = "1.1"
}

resource "azurerm_postgresql_server" "bad_example" {
	name                = "bad_example"
  
	public_network_access_enabled    = true
	ssl_enforcement_enabled          = false
	ssl_minimal_tls_version_enforced = "TLS1_1"
  }
`},
			GoodExample: []string{`
resource "azurerm_mssql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "missadministrator"
  administrator_login_password = "thisIsKat11"
  minimum_tls_version          = "1.2"
}

resource "azurerm_postgresql_server" "good_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_minimal_tls_version_enforced",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_mssql_server", "azurerm_mysql_server", "azurerm_postgresql_server"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			var attribute string
			var requiredValue string

			switch resourceBlock.TypeLabel() {
			case "azurerm_mssql_server":
				attribute = "minimum_tls_version"
				requiredValue = "1.2"
			case "azurerm_postgresql_server", "azurerm_mysql_server":
				attribute = "ssl_minimal_tls_version_enforced"
				requiredValue = "TLS1_2"
			}

			if resourceBlock.MissingChild(attribute) {
				if resourceBlock.TypeLabel() == "azurerm_mssql_server" {
					return
				}

				set.AddResult().
					WithDescription("Resource '%s' does not have %s set", resourceBlock.FullName(), attribute)
				return
			}

			tlsMinimumAttr := resourceBlock.GetAttribute(attribute)
			if tlsMinimumAttr.NotEqual(requiredValue) {
				set.AddResult().
					WithDescription("Resource '%s' has a value %s that is not %s", resourceBlock.FullName(), attribute, requiredValue).
					WithAttribute(tlsMinimumAttr)
			}
		},
	})
}
