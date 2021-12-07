package s3

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSIgnorePublicAclS3(t *testing.T) {
	expectedCode := "aws-s3-ignore-public-acls"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule fails when ignore public acls not set (default false)",
			source: `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule fails when ignore public acls explicitly set to false",
			source: `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = false
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule passes when ignore_public_acls present and set to true",
			source: `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}
 resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = true
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
