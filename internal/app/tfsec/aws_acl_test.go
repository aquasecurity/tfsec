package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSACL(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check aws_s3_bucket with acl=public-read",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read"
	logging = {}
}`,
			expectedResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=public-read-write",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read-write"
	logging = {}
}`,
			expectedResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=website",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "website"
	logging = {}
}`,
			expectedResultCode: checks.AWSBadBucketACL,
		},
		{
			name: "check aws_s3_bucket with acl=private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "private"
	logging = {}
}`,
			expectedResultCode: checks.None,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
