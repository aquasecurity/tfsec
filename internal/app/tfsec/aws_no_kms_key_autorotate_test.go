package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSNoKmsKeyAutoRotate(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name:                  "check KMS Key with auto-rotation not set",
			source:                `resource "aws_kms_key" "kms_key" {}`,
			mustIncludeResultCode: aws.AWSNoKMSAutoRotate,
		},
		{
			name: "check KMS Key with auto-rotation disabled",
			source: `
resource "aws_kms_key" "kms_key" {
	enable_key_rotation = false
}`,
			mustIncludeResultCode: aws.AWSNoKMSAutoRotate,
		},
		{
			name: "check KMS Key with auto-rotation enabled",
			source: `
resource "aws_kms_key" "kms_key" {
	enable_key_rotation = true
}`,
			mustExcludeResultCode: aws.AWSNoKMSAutoRotate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
