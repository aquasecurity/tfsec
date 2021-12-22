package cloudfront

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCloudFrontWafWebAclId(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-waf"
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check there is no waf web_acl_id for aws_cloudfront_distribution",
			source: `
 resource "aws_cloudfront_distribution" "s3_distribution" {
   origin_group {
     origin_id = "groupS3"
 
     failover_criteria {
       status_codes = [403, 404, 500, 502]
     }
 
     member {
       origin_id = "primaryS3"
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check there is a waf web_acl_id for aws_cloudfront_distribution",
			source: `
 resource "aws_cloudfront_distribution" "s3_distribution" {
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 
   web_acl_id = "waf_id"
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
