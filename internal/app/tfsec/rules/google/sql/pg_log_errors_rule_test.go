package sql
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GooglePgLogErrors(t *testing.T) {
// 	expectedCode := "google-sql-pg-log-errors"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "rule matches when flag is explicitly set to panic",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "log_min_messages"
// 			value = "PANIC"
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule matches when flag is explicitly set to ",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "log_min_messages"
// 			value = "FATAL"
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when debug is used",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// 	settings {
// 		database_flags {
// 			name  = "log_min_messages"
// 			value = "DEBUG1"
// 		}
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when default (warning) is used",
// 			source: `
// resource "google_sql_database_instance" "db" {
// 	name             = "db"
// 	database_version = "POSTGRES_12"
// 	region           = "us-central1"
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "rule does not match when postgres is not used",
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
