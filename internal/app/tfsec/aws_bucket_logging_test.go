package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSBucketLogging(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check bucket with logging disabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	
}`,
			expectedResultCode: checks.AWSNoBucketLogging,
		},
		{
			name: "check bucket with logging enabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	logging = {
		target_bucket = "target-bucket"
	}
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
