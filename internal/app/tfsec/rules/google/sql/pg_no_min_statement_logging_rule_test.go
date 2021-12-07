package sql
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GooglePgLogDurationStatement(t *testing.T) {
// 	expectedCode := "google-sql-pg-no-min-statement-logging"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "rule matches when flag is explicitly set to 99",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "log_min_duration_statement"
// 			value = "99"
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when flag is explicitly set to -1",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "log_min_duration_statement"
// 			value = "-1"
// 		}
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when flag is set to default (-1)",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
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
