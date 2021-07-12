package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSRestrictPublicBucketS3(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule fails when restrict public buckets is not set, defaults to false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}
`,
			mustIncludeResultCode: rules.AWSRestrictPublicBucketS3,
		},
		{
			name: "Rule fails when restrict public buckets is set but is false",
			source: `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = false
}
`,
			mustIncludeResultCode: rules.AWSRestrictPublicBucketS3,
		},
		{
			name: "Rule passes when restrict public buckets is set to true",
			source: `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = true
}
`,
			mustExcludeResultCode: rules.AWSRestrictPublicBucketS3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
