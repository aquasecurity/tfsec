package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSBucketLogging(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check bucket with logging disabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	
}`,
			mustIncludeResultCode: rules.AWSNoBucketLogging,
		},
		{
			name: "check bucket with logging enabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	logging {
		target_bucket = "target-bucket"
	}
}`,
			mustExcludeResultCode: rules.AWSNoBucketLogging,
		},
		{
			name: "check bucket with acl 'log-delivery-write' for logging",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "log-delivery-write"
}`,
			mustExcludeResultCode: rules.AWSNoBucketLogging,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
