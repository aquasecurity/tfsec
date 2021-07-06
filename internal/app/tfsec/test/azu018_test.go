package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUSQLDatabaseAuditingEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check fails when extended audit policy not configured",
			source: `
resource "azurerm_sql_server" "back_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"
}
`,
			mustIncludeResultCode: rules.AZUSQLDatabaseAuditingEnabled,
		},
		{
			name: "check fails when extended audit policy not configured on mssql server",
			source: `
resource "azurerm_mssql_server" "bad_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "tfsecRocks"
}
`,
			mustIncludeResultCode: rules.AZUSQLDatabaseAuditingEnabled,
		},
		{
			name: "check passes when extended audit policy is configured",
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
			mustExcludeResultCode: rules.AZUSQLDatabaseAuditingEnabled,
		},
		{
			name: "check passes when extended audit policy is configured on MSSQL",
			source: `
resource "azurerm_mssql_server" "good_example" {
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
			mustExcludeResultCode: rules.AZUSQLDatabaseAuditingEnabled,
		},
		{
			name: "check passes when separate azurerm_mssql_server_extended_auditing_policy is configured",
			source: `
			provider "azurerm" {
				features {}
			  }
			  
			  resource "azurerm_resource_group" "example" {
				name     = "example-resources"
				location = "West Europe"
			  }
			  
			  resource "azurerm_mssql_server" "example" {
				name                         = "example-sqlserver"
				resource_group_name          = azurerm_resource_group.example.name
				location                     = azurerm_resource_group.example.location
				version                      = "12.0"
				administrator_login          = "missadministrator"
				administrator_login_password = "AdminPassword123!"
			  }
			  
			  resource "azurerm_storage_account" "example" {
				name                     = "examplesa"
				resource_group_name      = azurerm_resource_group.example.name
				location                 = azurerm_resource_group.example.location
				account_tier             = "Standard"
				account_replication_type = "LRS"
			  }
			  
			  resource "azurerm_mssql_server_extended_auditing_policy" "example" {
				server_id                               = azurerm_mssql_server.example.id
				storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
				storage_account_access_key              = azurerm_storage_account.example.primary_access_key
				storage_account_access_key_is_secondary = false
				retention_in_days                       = 6
			  }`,
			mustExcludeResultCode: rules.AZUSQLDatabaseAuditingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
