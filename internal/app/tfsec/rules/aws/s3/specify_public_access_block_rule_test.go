package s3

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSS3BucketShouldHavePublicAccessBlock(t *testing.T) {
	expectedCode := "aws-s3-specify-public-access-block"

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
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
