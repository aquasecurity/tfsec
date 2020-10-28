package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEfsEncryptionNotEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name:                  "check if EFS Encryption is disabled",
			source:                `resource "aws_efs_file_system" "foo" {}`,
			mustIncludeResultCode: checks.AWSEfsEncryptionNotEnabled,
		},
		{
			name: "check if EFS Encryption is set to false",
			source: `
resource "aws_efs_file_system" "foo" {
  name                 = "bar"
  encrypted = false
  kms_key_id = ""
}`,
			mustIncludeResultCode: checks.AWSEfsEncryptionNotEnabled,
		},
		{
			name: "Encryption key is provided",
			source: `
resource "aws_efs_file_system" "foo" {
  name                 = "bar"
  encrypted = true
  kms_key_id = "my_encryption_key"
}`,
			mustExcludeResultCode: checks.AWSEfsEncryptionNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
