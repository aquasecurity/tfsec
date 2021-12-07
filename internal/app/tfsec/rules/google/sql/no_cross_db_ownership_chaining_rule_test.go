package sql
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GoogleNoCrossDbOwnershipChaining(t *testing.T) {
// 	expectedCode := "google-sql-no-cross-db-ownership-chaining"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "rule matches when cross db ownership chaining is not explicitly disabled",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "SQLSERVER_2017_STANDARD"
// 	region           = "us-central1"
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule matches when cross db ownership chaining is explicitly enabled",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "SQLSERVER_2017_STANDARD"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "cross db ownership chaining"
// 			value = "on"
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when cross db ownership chaining is explicitly disabled",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "SQLSERVER_2017_STANDARD"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "cross db ownership chaining"
// 			value = "off"
// 		}
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when sql server is not used",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "MYSQL_8_0"
// 	region           = "us-central1"
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// }
