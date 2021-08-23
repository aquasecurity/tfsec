package cloudfront
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSUnencryptedCloudFrontCommunications(t *testing.T) {
// 	expectedCode := "aws-cloudfront-enforce-https"
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check no default_cache_behavior in aws_cloudfront_distribution",
// 			source: `
// resource "aws_cloudfront_distribution" "s3_distribution" {
// 
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check no default viewer_protocol_policy in default_cache_behavior",
// 			source: `
// resource "aws_cloudfront_distribution" "s3_distribution" {
// 	default_cache_behavior {
// 
// 	  }
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check viewer_protocol_policy include allows-all",
// 			source: `
// resource "aws_cloudfront_distribution" "s3_distribution" {
// 	default_cache_behavior {
// 	    viewer_protocol_policy = "allow-all"
// 	  }
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check no viewer_protocol_policy in ordered_cache_behavior",
// 			source: `
// resource "aws_cloudfront_distribution" "s3_distribution" {
// 	default_cache_behavior {
// 		viewer_protocol_policy = "https-only"
// 	}
// 	
// 	# Cache behavior with precedence 0
// 	ordered_cache_behavior {
// 
// 	}
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check for allow-all in viewer_protocol_policy in orderd_cache_behavior ",
// 			source: `
// resource "aws_cloudfront_distribution" "s3_distribution" {
// 	default_cache_behavior {
// 		viewer_protocol_policy = "https-only"
// 	}
// 	
// 	# Cache behavior with precedence 0
// 	ordered_cache_behavior {
// 		viewer_protocol_policy = "allow-all"
// 	}
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// }
