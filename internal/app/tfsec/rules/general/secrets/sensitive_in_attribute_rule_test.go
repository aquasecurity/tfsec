package secrets

 generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSSensitiveAttributes(t *testing.T) {
	expectedCode := "general-secrets-sensitive-in-attribute"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check sensitive attribute",
			source: `
 resource "evil_corp" "virtual_machine" {
 	root_password = "secret"
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check non-sensitive local",
			source: `
 resource "evil_corp" "virtual_machine" {
 	memory = 512
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "avoid false positive for aws_efs_file_system",
			source: `
 resource "aws_efs_file_system" "myfs" {
 	creation_token = "something"
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "avoid false positive for google_secret_manager_secret",
			source: `
 resource "google_secret_manager_secret" "secret" {
 	secret_id = "secret"
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "avoid false positive for non-string attributes",
			source: `
 resource "something" "secret" {
 	secret = true
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

func Test_GitHubSensitiveAttributes(t *testing.T) {
	expectedCode := "general-secrets-sensitive-in-attribute"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "avoid false positive for github_actions_secret",
			source: `
 resource "github_actions_secret" "infrastructure_digitalocean_deploy_user" {
 	secret_name = "digitalocean_deploy_user"
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
