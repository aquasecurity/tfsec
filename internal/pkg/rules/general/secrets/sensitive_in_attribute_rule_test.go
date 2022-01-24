package secrets

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/testutil"
)

func Test_AWSSensitiveAttributes(t *testing.T) {
	expectedCode := "general-secrets-no-plaintext-exposure"

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
		{
			name: "avoid vault pki false positive",
			source: `
provider "vault" {
  address = var.vault_address
  token   = var.vault_token
}

resource "vault_pki_secret_backend_cert" "server_cert" {
  backend     = var.vault_backend
  name        = var.vault_name
  common_name = var.server_name
  format = "pem"
  # this line is flagged
  private_key_format = "pkcs8"
}

            `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "kubernetes_service_account automount_service_account_token",
			source: `
resource "kubernetes_service_account" "rule_breaker" {
  metadata {
    name      = var.name
    namespace = var.namespace
  }
  automount_service_account_token = "true"
}
            `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			if test.mustIncludeResultCode != "" {
				testutil.AssertRuleFound(t, test.mustIncludeResultCode, results, "false negative found")
			}
			if test.mustExcludeResultCode != "" {
				testutil.AssertRuleNotFound(t, test.mustExcludeResultCode, results, "false positive found")
			}
		})
	}
}

func Test_GitHubSensitiveAttributes(t *testing.T) {
	expectedCode := "general-secrets-no-plaintext-exposure"

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
			if test.mustIncludeResultCode != "" {
				testutil.AssertRuleFound(t, test.mustIncludeResultCode, results, "false negative found")
			}
			if test.mustExcludeResultCode != "" {
				testutil.AssertRuleNotFound(t, test.mustExcludeResultCode, results, "false positive found")
			}
		})
	}
}
