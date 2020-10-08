package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSIamPasswordReusePrevention(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}`,
			mustIncludeResultCode: checks.AWSIAMPasswordReusePrevention,
		},
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention less than 5",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 4
}`,
			mustIncludeResultCode: checks.AWSIAMPasswordReusePrevention,
		},
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention greater than 5",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 5
}`,
			mustExcludeResultCode: checks.AWSIAMPasswordReusePrevention,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
