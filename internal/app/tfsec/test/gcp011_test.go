package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GoogleUserIAMGrant(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check google_project_iam_binding with grant to user identity",
			source: `
resource "google_project_iam_binding" "project-binding" {
	members = [
		"user:test@example.com",
		]
}`,
			mustIncludeResultCode: checks.GoogleUserIAMGrant,
		},
		{
			name: "check google_project_iam_binding with grant to user identity",
			source: `
resource "google_project_iam_binding" "project-binding" {
	members = [
		"group:test@example.com",
		]
}`,
			mustExcludeResultCode: checks.GoogleUserIAMGrant,
		},
		{
			name: "check google_project_iam_member with grant to user identity",
			source: `
resource "google_project_iam_member" "project-member" {
	member = "user:test@example.com"
}`,
			mustIncludeResultCode: checks.GoogleUserIAMGrant,
		},
		{
			name: "check google_storage_bucket_iam_binding with grant to user identity",
			source: `
resource "google_storage_bucket_iam_binding" "bucket-binding" {
	members = [
		"user:test@example.com",
		]
}`,
			mustIncludeResultCode: checks.GoogleUserIAMGrant,
		},
		{
			name: "check google_storage_bucket_iam_member with grant to user identity",
			source: `
resource "google_storage_bucket_iam_member" "bucket-member" {
	member = "user:test@example.com"
}`,
			mustIncludeResultCode: checks.GoogleUserIAMGrant,
		},
		{
			name: "check google_storage_bucket_iam_member with grant to service account identity",
			source: `
resource "google_storage_bucket_iam_member" "bucket-member" {
	member = "serviceAccount:test@example.com"
}`,
			mustExcludeResultCode: checks.GoogleUserIAMGrant,
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
			mustIncludeResultCode: checks.GoogleUserIAMGrant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
