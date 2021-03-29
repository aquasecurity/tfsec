package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSBlockPublicPolicyS3(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check fails when block_public_policy not set, defaults to false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}
`,
			mustIncludeResultCode: checks.AWSBlockPublicPolicyS3,
		},
		{
			name: "Check fails when block_public_policy set but is false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id

	block_public_policy = false
}
`,
			mustIncludeResultCode: checks.AWSBlockPublicPolicyS3,
		},
		{
			name: "Check passes when block_public_policy is true",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id

	block_public_policy = true
}
`,
			mustExcludeResultCode: checks.AWSBlockPublicPolicyS3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
