package sql

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GooglePgLogCheckpoints(t *testing.T) {
	expectedCode := "google-sql-pg-log-checkpoints"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "rule matches when flag is explicitly set to off",
			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_checkpoints"
 			value = "off"
 		}
 	}
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule matches when flag is set to default (off)",
			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when flag is set to on",
			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_checkpoints"
 			value = "on"
 		}
 	}
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when not postgres",
			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
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
