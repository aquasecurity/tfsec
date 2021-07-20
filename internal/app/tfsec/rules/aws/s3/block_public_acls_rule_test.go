package s3

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSBlockPublicAclS3(t *testing.T) {
	expectedCode := "aws-s3-block-public-acls"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule fails when block_public_acls not set, defaults to false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule fails when block_public_acls set but false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_acls = false
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule passes when block_public_acls set to true",
			source: `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_acls = true
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
