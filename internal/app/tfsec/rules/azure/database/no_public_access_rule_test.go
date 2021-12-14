package database
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AzureNoPublicAccess(t *testing.T) {
 	expectedCode := "azure-database-no-public-access"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "server with public access enabled fails check",
 			source: `
 resource "azurerm_postgresql_server" "bad_example" {
   name                = "bad_example"
 
   public_network_access_enabled    = true
   ssl_enforcement_enabled          = false
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "server with public access not set fails check",
 			source: `
 resource "azurerm_mariadb_server" "bad_example" {
   name                = "bad_example"
 
 
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "server public access disabled passes check",
 			source: `
 resource "azurerm_mysql_server" "goodl_example" {
   name                = "goodl_example"
 
   public_network_access_enabled    = false
   ssl_enforcement_enabled          = true
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
