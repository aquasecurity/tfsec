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
			name: "Check does not pass when logging_config is missing in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "bad_example" {
	// other config
	// no logging_config
}
`,
			mustIncludeResultCode: checks.AWSCloudfrontDistributionAccessLoggingEnabled,
		},
		{
			name: "Check passes when logging_config is declared in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "good_example" {
	// other config
	logging_config {
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
