package sql

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GoogleMysqlNoLocalInfile(t *testing.T) {
	expectedCode := "google-sql-mysql-no-local-infile"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "rule matches when flag is enabled",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "MYSQL_5_6"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "local_infile"
			value = "on"
		}
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when flag is disabled",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "MYSQL_5_6"
	region           = "us-central1"
	settings {
		database_flags {
			name  = "local_infile"
			value = "off"
		}
	}
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "rule does not match when flag is defaulted (to disabled)",
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
