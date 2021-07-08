package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSS3BucketShouldHavePublicAccessBlock(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Should fail when a bucket is missing the public access block",
			source: `
resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = "private-read"
}
`,
			mustIncludeResultCode: rules.AWSS3BucketShouldHavePublicAccessBlock,
		},
		{
			name: "Should pass when a bucket is not missing the public access block",
			source: `
resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = "private-read"
}
  
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls   = true
  block_public_policy = true
}
`,
			mustExcludeResultCode: rules.AWSS3BucketShouldHavePublicAccessBlock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
