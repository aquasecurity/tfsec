package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSCloudFrontDoesNotHaveAWaf See https://github.com/tfsec/tfsec#included-checks for check info
const AWSCloudFrontDoesNotHaveAWaf = "AWS045"
const AWSCloudFrontDoesNotHaveAWafDescription = "CloudFront distribution does not have a WAF in front."
const AWSCloudFrontDoesNotHaveAWafImpact = "Complex web application attacks can more easily be performed without a WAF"
const AWSCloudFrontDoesNotHaveAWafResolution = "Enable WAF for the CloudFront distribution"
const AWSCloudFrontDoesNotHaveAWafExplanation = `
You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.
`
const AWSCloudFrontDoesNotHaveAWafBadExample = `
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
`
const AWSCloudFrontDoesNotHaveAWafGoodExample = `
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudFrontDoesNotHaveAWaf,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSCloudFrontDoesNotHaveAWafDescription,
			Impact:      AWSCloudFrontDoesNotHaveAWafImpact,
			Resolution:  AWSCloudFrontDoesNotHaveAWafResolution,
			Explanation: AWSCloudFrontDoesNotHaveAWafExplanation,
			BadExample:  AWSCloudFrontDoesNotHaveAWafBadExample,
			GoodExample: AWSCloudFrontDoesNotHaveAWafGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id",
				"https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(block *block.Block, context *hclcontext.Context) []result.Result {

			wafAclIdBlock := block.GetAttribute("web_acl_id")
			if wafAclIdBlock == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not have a WAF in front of it.", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				}
			}
			return nil
		},
	})
}
