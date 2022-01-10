package cloudfront

import (
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS045",
		BadExample: []string{`
 resource "aws_cloudfront_distribution" "bad_example" {
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
 }
 `},
		GoodExample: []string{`
 resource "aws_cloudfront_distribution" "good_example" {
 
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
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		Base:           cloudfront.CheckEnableWaf,
	})
}
