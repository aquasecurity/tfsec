package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSACL(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_s3_bucket with acl=public-read",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read"
	logging {}
}`,
			mustIncludeResultCode: rules.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=public-read-write",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read-write"
	logging {}
}`,
			mustIncludeResultCode: rules.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=website",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "website"
}`,
			mustIncludeResultCode: rules.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "private"
}`,
			mustExcludeResultCode: rules.AWSBadBucketACL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
