package database

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureSecureTlsPolicy(t *testing.T) {
	expectedCode := "azure-database-secure-tls-policy"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "msql with incorrect tls fails check",
			source: `
resource "azurerm_mssql_server" "bad_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "missadministrator"
  administrator_login_password = "thisIsKat11"
  minimum_tls_version          = "1.1"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "postgresql with incorrect tls fails check",
			source: `
resource "azurerm_postgresql_server" "bad_example" {
	name                = "bad_example"
  
	public_network_access_enabled    = true
	ssl_enforcement_enabled          = false
	ssl_minimal_tls_version_enforced = "TLS1_1"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "mysql with incorrect tls fails check",
			source: `
resource "azurerm_mysql_server" "bad_example" {
	name                = "bad_example"
  
	public_network_access_enabled    = true
	ssl_enforcement_enabled          = false
	ssl_minimal_tls_version_enforced = "TLS1_1"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "mssql with correct tls passes check",
			source: `
resource "azurerm_mssql_server" "example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "missadministrator"
  administrator_login_password = "thisIsKat11"
  minimum_tls_version          = "1.2"
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "postgresql with correct tls passes check",
			source: `
resource "azurerm_postgresql_server" "good_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "mysql with correct tls passes check",
			source: `
resource "azurerm_mysql_server" "good_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
