package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedCloudFrontCommunications(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no default_cache_behavior in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {

}`,
			mustIncludeResultCode: rules.AWSUnencryptedCloudFrontCommunications,
		},
		{
			name: "check no default viewer_protocol_policy in default_cache_behavior",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {

	  }
}`,
			mustIncludeResultCode: rules.AWSUnencryptedCloudFrontCommunications,
		},
		{
			name: "check viewer_protocol_policy include allows-all",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {
	    viewer_protocol_policy = "allow-all"
	  }
}`,
			mustIncludeResultCode: rules.AWSUnencryptedCloudFrontCommunications,
		},
		{
			name: "check no viewer_protocol_policy in ordered_cache_behavior",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {
		viewer_protocol_policy = "https-only"
	}
	
	# Cache behavior with precedence 0
	ordered_cache_behavior {

	}
}`,
			mustIncludeResultCode: rules.AWSUnencryptedCloudFrontCommunications,
		},
		{
			name: "check for allow-all in viewer_protocol_policy in orderd_cache_behavior ",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {
		viewer_protocol_policy = "https-only"
	}
	
	# Cache behavior with precedence 0
	ordered_cache_behavior {
		viewer_protocol_policy = "allow-all"
	}
}`,
			mustIncludeResultCode: rules.AWSUnencryptedCloudFrontCommunications,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
