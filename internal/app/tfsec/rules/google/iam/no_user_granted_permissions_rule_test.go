package iam

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GoogleUserIAMGrant(t *testing.T) {
	expectedCode := "google-iam-no-user-granted-permissions"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_project_iam_binding with grant to user identity",
			source: `
resource "google_project_iam_binding" "project-binding" {
	members = [
		"user:test@example.com",
		]
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_project_iam_binding with grant to user identity",
			source: `
resource "google_project_iam_binding" "project-binding" {
	members = [
		"group:test@example.com",
		]
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check google_project_iam_member with grant to user identity",
			source: `
resource "google_project_iam_member" "project-member" {
	member = "user:test@example.com"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_storage_bucket_iam_binding with grant to user identity",
			source: `
resource "google_storage_bucket_iam_binding" "bucket-binding" {
	members = [
		"user:test@example.com",
		]
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_storage_bucket_iam_member with grant to user identity",
			source: `
resource "google_storage_bucket_iam_member" "bucket-member" {
	member = "user:test@example.com"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_storage_bucket_iam_member with grant to service account identity",
			source: `
resource "google_storage_bucket_iam_member" "bucket-member" {
	member = "serviceAccount:test@example.com"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check data.google_iam_policy with grant to user",
			source: `
data "google_iam_policy" "test-policy" {
	binding {
		members = [
			"group:test@example.com",
			"user:test@example.com",
		]
	}
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check data.google_iam_policy with grant to interpolated values",
			source: `
data "google_iam_policy" "test-policy" {
	binding {
		members = [
			"serviceAccount:${google_service_account.service_account.email}"
		]
	}
}`,
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
