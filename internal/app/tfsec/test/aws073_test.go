package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSIngorePublicAclS3(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check fails when ignore public acls not set (default false)",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}
`,
			mustIncludeResultCode: checks.AWSIngorePublicAclS3,
		},
		{
			name: "Check fails when ignore public acls explicitly set to false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = false
}
`,
			mustIncludeResultCode: checks.AWSIngorePublicAclS3,
		},
		{
			name: "Check passes when ignore_public_acls present and set to true",
			source: `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = true
}
`,
			mustExcludeResultCode: checks.AWSIngorePublicAclS3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
