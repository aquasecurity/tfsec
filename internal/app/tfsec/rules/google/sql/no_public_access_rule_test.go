package sql
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GoogleNoPublicAccess(t *testing.T) {
// 	expectedCode := "google-sql-no-public-access"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check detects issue with public ipv4 address being assigned",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// 	settings {
// 		tier = "db-f1-micro"
// 	
// 		ip_configuration {
// 			ipv4_enabled = true
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check detects issue with public ipv4 address being assigned by default",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// 	settings {
// 			tier = "db-f1-micro"
// 	
// 			ip_configuration {
// 			}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check detects issue with public ipv4 address being assigned by default",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// 	settings {
// 		tier = "db-f1-micro"
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check detects issue with public ipv4 address being assigned by default",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check detects issue with authorized network being internet",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// 	settings {
// 		tier = "db-f1-micro"
// 	
// 		ip_configuration {
// 			ipv4_enabled = false
// 			authorized_networks {
// 				value           = "108.12.12.0/24"
// 				name            = "internal"
// 			}
// 	
// 			authorized_networks {
// 				value           = "0.0.0.0/0"
// 				name            = "internet"
// 			}
// 		}
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check detects no issue with authorized network being internal",
// 			source: `
// resource "google_sql_database_instance" "postgres" {
// 	name             = "postgres-instance-a"
// 	database_version = "POSTGRES_11"
// 	
// 	settings {
// 		tier = "db-f1-micro"
// 	
// 		ip_configuration {
// 			ipv4_enabled = false
// 			authorized_networks {
// 				value           = "108.12.12.0/24"
// 				name            = "internal"
// 			}
// 		}
// 	}
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
