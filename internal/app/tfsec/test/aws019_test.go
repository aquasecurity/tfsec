package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSNoKmsKeyAutoRotate(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check KMS Key with auto-rotation not set",
			source:                `resource "aws_kms_key" "kms_key" {}`,
			mustIncludeResultCode: rules.AWSNoKMSAutoRotate,
		},
		{
			name: "check KMS Key with auto-rotation disabled",
			source: `
resource "aws_kms_key" "kms_key" {
	enable_key_rotation = false
}`,
			mustIncludeResultCode: rules.AWSNoKMSAutoRotate,
		},
		{
			name: "check KMS Key with auto-rotation enabled",
			source: `
resource "aws_kms_key" "kms_key" {
	enable_key_rotation = true
}`,
			mustExcludeResultCode: rules.AWSNoKMSAutoRotate,
		},
		{
			name: "check SIGN_VERIFY KMS Key with auto-rotation disabled",
			source: `
resource "aws_kms_key" "kms_key" {
	key_usage = "SIGN_VERIFY"
}`,
			mustExcludeResultCode: rules.AWSNoKMSAutoRotate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
