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

const AWSCloudfrontDistributionViewerProtocolPolicyHTTPS = "AWS072"
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSDescription = "Viewer Protocol Policy in Cloudfront Distribution Cache should always be set to HTTPS"
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSImpact = "HTTP traffic can be read if intercepted"
const AWSCloudfrontDistributionViewerProtocolPolicyHTTPSResolution = "Only use HTTPS in the Viewer Protocol Policy"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSCloudfrontDistributionViewerProtocolPolicyHTTPSDescription,
			Impact:      AWSCloudfrontDistributionViewerProtocolPolicyHTTPSImpact,
			Resolution:  AWSCloudfrontDistributionViewerProtocolPolicyHTTPSResolution,
			Explanation: AWSCloudfrontDistributionViewerProtocolPolicyHTTPSExplanation,
			BadExample:  AWSCloudfrontDistributionViewerProtocolPolicyHTTPSBadExample,
			GoodExample: AWSCloudfrontDistributionViewerProtocolPolicyHTTPSGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {

			defaultCacheBlock := resourceBlock.GetBlock("default_cache_behavior")
			if defaultCacheBlock.GetAttribute("viewer_protocol_policy").Equals("allow-all", block.IgnoreCase) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not use HTTPS in Viewer Protocol Policy", resourceBlock.FullName())).
						WithRange(defaultCacheBlock.Range()).
						WithSeverity(severity.Error),
				)
			}

			orderedCacheBlocks := resourceBlock.GetBlocks("ordered_cache_behavior")
			for _, orderedCacheBlock := range orderedCacheBlocks {
				if orderedCacheBlock.GetAttribute("viewer_protocol_policy").Equals("allow-all", block.IgnoreCase) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' does not use HTTPS in Viewer Protocol Policy", resourceBlock.FullName())).
							WithRange(orderedCacheBlock.Range()).
							WithSeverity(severity.Error),
					)
				}
			}

		},
	})
}
