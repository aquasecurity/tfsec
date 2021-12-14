package storage
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_GoogleNoPublicAccess(t *testing.T) {
 	expectedCode := "google-storage-no-public-access"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "detects issue with iam_binding using allAuthenticatedUsers",
 			source: `
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"allAuthenticatedUsers",
 	]
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "detects issue with iam_binding using ",
 			source: `
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"allUsers",
 	]
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "detects issue with iam_member using allAuthenticatedUsers",
 			source: `
 resource "google_storage_bucket_iam_member" "member" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	member = "allAuthenticatedUsers"
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "detects issue with iam_member using allUsers",
 			source: `
 resource "google_storage_bucket_iam_member" "member" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	member = "allUsers"
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "detects no issue for iam_binding when public access is not configured",
 			source: `
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"user:someone@example.com",
 	]
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "detects no issue for iam_member when public access is not configured",
 			source: `
 resource "google_storage_bucket_iam_member" "member" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	member = "user:someone@example.com"
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
