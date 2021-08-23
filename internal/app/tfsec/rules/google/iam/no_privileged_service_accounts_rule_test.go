package iam
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GoogleNoPrivilegedServiceAccounts(t *testing.T) {
// 	expectedCode := "google-iam-no-privileged-service-accounts"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "Rule matches when service account is assigned a privileged role (owner)",
// 			source: `
// 		resource "google_project_iam_member" "project" {
// 			project = "your-project-id"
// 			role    = "roles/owner"
// 			member  = "serviceAccount:test@test.com"
// 		}
// 		`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule matches when service account is assigned a privileged role (admin)",
// 			source: `
// 		resource "google_project_iam_member" "project" {
// 			project = "your-project-id"
// 			role    = "roles/admin"
// 			member  = "serviceAccount:test@test.com"
// 		}
// 		`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule matches when service account is assigned a privileged role (editor)",
// 			source: `
// 		resource "google_project_iam_member" "project" {
// 			project = "your-project-id"
// 			role    = "roles/editor"
// 			member  = "serviceAccount:test@test.com"
// 		}
// 		`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule matches when service account is assigned a privileged role via templated reference",
// 			source: `
// resource "google_service_account" "test" {
// 	account_id   = "account123"
// 	display_name = "account123"
// }
// 
// resource "google_project_iam_member" "project" {
// 	project = "your-project-id"
// 	role    = "roles/owner"
// 	member  = "serviceAccount:${google_service_account.test.email}"
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule not not match when service account is assigned an unprivileged role",
// 			source: `
// resource "google_service_account" "test" {
// 	account_id   = "account123"
// 	display_name = "account123"
// }
// 
// resource "google_project_iam_member" "project" {
// 	project = "your-project-id"
// 	role    = "roles/logging.logWriter"
// 	member  = "serviceAccount:${google_service_account.test.email}"
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
