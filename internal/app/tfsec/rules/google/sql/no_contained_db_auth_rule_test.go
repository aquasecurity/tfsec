package sql

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GoogleNoContainedDbAuth(t *testing.T) {
	expectedCode := "google-sql-no-contained-db-auth"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "TODO: add test name",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "SQLSERVER_2017_STANDARD"
	region           = "us-central1"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "TODO: add test name",
			source: `
resource "google_sql_database_instance" "db" {
	name             = "db"
	database_version = "SQLSERVER_2017_STANDARD"
	region           = "us-central1"
	settings {
		database_flags {
		    name  = "contained database authentication"
			value = "off"
		}
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
