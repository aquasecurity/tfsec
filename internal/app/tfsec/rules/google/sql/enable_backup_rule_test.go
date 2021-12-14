package sql
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_GoogleEnableBackup(t *testing.T) {
 	expectedCode := "google-sql-enable-backup"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "rule matches when backups are disabled explicitly",
 			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = false
 		}
 	}
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "rule matches when backups are disabled by default",
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
 			name: "rule does not match when backups are enabled",
 			source: `
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = true
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
