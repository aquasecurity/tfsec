package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSBlockPublicPolicyS3(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule fails when block_public_policy not set, defaults to false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}
`,
			mustIncludeResultCode: rules.AWSBlockPublicPolicyS3,
		},
		{
			name: "Rule fails when block_public_policy set but is false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id

	block_public_policy = false
}
`,
			mustIncludeResultCode: rules.AWSBlockPublicPolicyS3,
		},
		{
			name: "Rule passes when block_public_policy is true",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id

	block_public_policy = true
}
`,
			mustExcludeResultCode: rules.AWSBlockPublicPolicyS3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
