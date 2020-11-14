package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUDatabaseAuditingRetention90Days(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check fails if retention period is less than 90",
			source: `
resource "azurerm_mssql_database_extended_auditing_policy" "bad_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 10
}
`,
			mustIncludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		},
		{
			name: "check fails if extended_auditing_policy has retention less than 90 days",
			source: `
resource "azurerm_sql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }
}
`,
			mustIncludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		},
		{
			name: "check passes if retention not specified",
			source: `
resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
}
`,
			mustExcludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		}, {
			name: "check passes if the extended_auditing_policy has retention not specified",
			source: `
resource "azurerm_sql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
  }
}
`,
			mustExcludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		},
		{
			name: "check passes if retention period is greatet than or equal 90",
			source: `
resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
}
`,
			mustExcludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		},
		{
			name: "check passes if extended auditing policy has retention period is greatet than or equal 90",
			source: `
resource "azurerm_sql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
	retention_in_days                       = 90
  }
}
`,
			mustExcludeResultCode: checks.AZUDatabaseAuditingRetention90Days,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
