package database

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUDatabaseAuditingRetention90Days(t *testing.T) {
	expectedCode := "azure-database-retention-period-set"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check fails if retention period is less than 90",
			source: `
 resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
 }

 resource "azurerm_mssql_database" "example" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
 }

 resource "azurerm_mssql_database_extended_auditing_policy" "bad_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
   retention_in_days                       = 10
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check passes if retention period is unlimited (0)",
			source: `
 resource "azurerm_mssql_server" "example" {
   name                         = "example-sqlserver"
 }

   resource "azurerm_mssql_database" "example" {
   name      = "example-db"
   server_id = azurerm_mssql_server.example.id
 }
      
 resource "azurerm_mssql_database_extended_auditing_policy" "unlimited_retention" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
   retention_in_days                       = 0
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check fails if extended_auditing_policy has retention less than 90 days",
			source: `
 resource "azurerm_mssql_server" "example" {
    name                         = "example-sqlserver"
  }
  
 resource "azurerm_mssql_database" "example" {
   name      = "example-db"
   server_id = azurerm_mssql_server.example.id
 }

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check passes if retention not specified",
			source: `
 resource "azurerm_mssql_server" "example" {
   name                         = "example-sqlserver"
 }

 resource "azurerm_mssql_database" "example" {
   name      = "example-db"
   server_id = azurerm_mssql_server.example.id
 }

 resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
 }
 `,
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check passes if retention period is greater than or equal 90",
			source: `
 resource "azurerm_mssql_server" "example" {
   name                         = "example-sqlserver"
 }

 resource "azurerm_mssql_database" "example" {
   name      = "example-db"
   server_id = azurerm_mssql_server.example.id
 }

 resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
   retention_in_days                       = 90
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check passes if extended auditing policy has retention period is greater than or equal 90",
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
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check passes if extended auditing policy is unlimited retention",
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
     retention_in_days                        = 0
   }
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
