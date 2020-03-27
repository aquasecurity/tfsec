package tfsec

import (
	"github.com/liamg/tfsec/internal/app/tfsec/checks"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
	"testing"
)

func Test_AWSCloudFrontOutdatedProtocol(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check no viewer_certificate block in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {

}`,
			mustIncludeResultCode: checks.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check no default minimum_protocol_version attribute in viewer_certificate block",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}`,
			mustIncludeResultCode: checks.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check TLSv1.2_2018 not used",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.1_2016"
  }
}`,
			mustIncludeResultCode: checks.AWSCloudFrontOutdatedProtocol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
