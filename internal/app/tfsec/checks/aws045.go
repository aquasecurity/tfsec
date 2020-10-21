package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSCloudFrontDoesNotHaveAWaf See https://github.com/tfsec/tfsec#included-checks for check info
const AWSCloudFrontDoesNotHaveAWaf scanner.RuleCode = "AWS045"
const AWSCloudFrontDoesNotHaveAWafDescription scanner.RuleSummary = "CloudFront distribution does not have a WAF in front."
const AWSCloudFrontDoesNotHaveAWafExplanation = `
You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.
`
const AWSCloudFrontDoesNotHaveAWafBadExample = `
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
}
`
const AWSCloudFrontDoesNotHaveAWafGoodExample = `
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
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudFrontDoesNotHaveAWaf,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudFrontDoesNotHaveAWafDescription,
			Explanation: AWSCloudFrontDoesNotHaveAWafExplanation,
			BadExample:  AWSCloudFrontDoesNotHaveAWafBadExample,
			GoodExample: AWSCloudFrontDoesNotHaveAWafGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			wafAclIdBlock := block.GetAttribute("web_acl_id")
			if wafAclIdBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a WAF in front of it.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
