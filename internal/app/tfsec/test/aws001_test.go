package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSACL(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_s3_bucket with acl=public-read",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read"
	logging {}
}`,
			mustIncludeResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=public-read-write",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read-write"
	logging {}
}`,
			mustIncludeResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=website",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "website"
}`,
			mustIncludeResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "private"
}`,
			mustExcludeResultCode: checks.AWSBadBucketACL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
