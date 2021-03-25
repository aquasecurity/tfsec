package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSCloudfrontDistributionAccessLoggingEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check no logging_config in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "bad_example" {
	// other config
	// no logging_config
}
`,
			mustIncludeResultCode: checks.AWSCloudfrontDistributionAccessLoggingEnabled,
		},
		{
			name: "check aws_cloudfront_distribution with existing logging_config",
			source: `
resource "aws_cloudfront_distribution" "good_example" {
	// other config
	logging_config {
		include_cookies = false
		bucket          = "mylogs.s3.amazonaws.com"
		prefix          = "myprefix"
	}
}
`,
			mustExcludeResultCode: checks.AWSCloudfrontDistributionAccessLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
