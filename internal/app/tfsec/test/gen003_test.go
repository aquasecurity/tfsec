package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSSensitiveAttributes(t *testing.T) {

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
			mustIncludeResultCode: rules.GenericSensitiveAttributes,
		},
		{
			name: "check non-sensitive local",
			source: `
resource "evil_corp" "virtual_machine" {
	memory = 512
}`,
			mustExcludeResultCode: rules.GenericSensitiveAttributes,
		},
		{
			name: "avoid false positive for aws_efs_file_system",
			source: `
resource "aws_efs_file_system" "myfs" {
	creation_token = "something"
}`,
			mustExcludeResultCode: rules.GenericSensitiveAttributes,
		},
		{
			name: "avoid false positive for google_secret_manager_secret",
			source: `
resource "google_secret_manager_secret" "secret" {
	secret_id = "secret"
}`,
			mustExcludeResultCode: rules.GenericSensitiveAttributes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_GitHubSensitiveAttributes(t *testing.T) {

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
			mustExcludeResultCode: rules.GenericSensitiveAttributes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
