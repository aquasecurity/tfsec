package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSEfsEncryptionNotEnabled(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name:                  "check if EFS Encryption is disabled",
			source:                `resource "aws_efs_file_system" "foo" {}`,
			mustIncludeResultCode: checks.AWSEfsEncryptionNotEnabled,
		},
		{
			name: "check if EFS Encryption is disabled",
			source: `
resource "aws_efs_file_system" "foo" {
  name                 = "bar"
  encrypted = "bar"
  kms_key_id = ""
}`,
			mustIncludeResultCode: checks.AWSEfsEncryptionNotEnabled,
		},
		{
			name: "check if EFS Encryption is disabled",
			source: `
resource "aws_efs_file_system" "foo" {
  name                 = "bar"
  encrypted = "bar"
  kms_key_id = ""
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
