package s3

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSBucketLogging(t *testing.T) {
	expectedCode := "aws-s3-enable-bucket-logging"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check bucket with logging enabled",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	logging {
		target_bucket = "target-bucket"
	}
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check bucket with acl 'log-delivery-write' for logging",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "log-delivery-write"
}`,
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
