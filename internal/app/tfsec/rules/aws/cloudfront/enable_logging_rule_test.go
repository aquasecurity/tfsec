package cloudfront

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCloudfrontDistributionAccessLoggingEnabled(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-logging"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule does not pass when logging_config is missing in aws_cloudfront_distribution",
			source: `
 resource "aws_cloudfront_distribution" "bad_example" {
 	// other config
 	// no logging_config
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule passes when logging_config is declared in aws_cloudfront_distribution",
			source: `
 resource "aws_cloudfront_distribution" "good_example" {
 	// other config
 	logging_config {
 	}
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
