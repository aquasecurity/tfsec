package sql

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GoogleEnablePgTempFileLogging(t *testing.T) {
	expectedCode := "google-sql-enable-pg-temp-file-logging"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "rule matches when flag is not explicitly set (defaults to -1)",
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
			name: "rule matches when flag is set to '-1'",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "log_temp_files"
			value = "-1"
		}
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule matches when flag is set to '512'",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "log_temp_files"
			value = "512"
		}
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when flag is set to '0'",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "POSTGRES_12"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "log_temp_files"
			value = "0"
		}
	}
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when postgres is not used",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "MYSQL_8_0"
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
