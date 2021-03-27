package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudfrontDistributionViewerProtocolPolicyHTTPS scanner.RuleCode = "AWS072"
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSDescription scanner.RuleSummary = "Viewer Protocol Policy in Cloudfront Distribution Cache should always be set to HTTPS"
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSExplanation = `
CloudFront connections should be encrypted during transmission over networks that can be accessed by malicious individuals. 
A CloudFront distribution should only use HTTPS or Redirect HTTP to HTTPS for communication between viewers and CloudFront.
`
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSBadExample = `
resource "aws_cloudfront_distribution" "bad_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "allow-all" // including HTTP
	}
}

resource "aws_cloudfront_distribution" "bad_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" // HTTPS by default...
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "allow-all" // ...but HTTP for some other resources
	}
}
`
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSGoodExample = `
resource "aws_cloudfront_distribution" "good_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" 
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "redirect-to-https"
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudfrontDistributionViewerProtocolPolicyHTTPSDescription,
			Explanation: AWSCloudfrontDistributionViewerProtocolPolicyHTTPSExplanation,
			BadExample:  AWSCloudfrontDistributionViewerProtocolPolicyHTTPSBadExample,
			GoodExample: AWSCloudfrontDistributionViewerProtocolPolicyHTTPSGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			defaultCacheBlock := block.GetBlock("default_cache_behavior")
			if defaultCacheBlock.GetAttribute("viewer_protocol_policy").Equals("allow-all", parser.IgnoreCase) {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Cloudfront distribution cache '%s' does not use HTTPS in Viewer Protocol Policy", block.FullName()),
						defaultCacheBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			orderedCacheBlocks := block.GetBlocks("ordered_cache_behavior")
			for _, orderedCacheBlock := range orderedCacheBlocks {
				if orderedCacheBlock.GetAttribute("viewer_protocol_policy").Equals("allow-all", parser.IgnoreCase) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Cloudfront distribution cache '%s' does not use HTTPS in Viewer Protocol Policy", block.FullName()),
							orderedCacheBlock.Range(),
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
