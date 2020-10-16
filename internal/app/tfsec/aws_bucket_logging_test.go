package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSBucketLogging(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check bucket with logging disabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	
}`,
			mustIncludeResultCode: aws.AWSNoBucketLogging,
		},
		{
			name: "check bucket with logging enabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	logging {
		target_bucket = "target-bucket"
	}
}`,
			mustExcludeResultCode: aws.AWSNoBucketLogging,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
