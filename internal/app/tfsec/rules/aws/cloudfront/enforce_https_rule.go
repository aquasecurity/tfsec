package cloudfront

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS020",
		Service:   "cloudfront",
		ShortCode: "enforce-https",
		Documentation: rule.RuleDocumentation{
			Summary:    "CloudFront distribution allows unencrypted (HTTP) communications.",
			Impact:     "CloudFront is available through an unencrypted connection",
			Resolution: "Only allow HTTPS for CloudFront distribution communication",
			Explanation: `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`,
			BadExample: []string{`
resource "aws_cloudfront_distribution" "bad_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "allow-all"
	  }
}
`},
			GoodExample: []string{`
resource "aws_cloudfront_distribution" "good_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "redirect-to-https"
	  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			defaultBehaviorBlock := resourceBlock.GetBlock("default_cache_behavior")
			if defaultBehaviorBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing default_cache_behavior block).", resourceBlock.FullName())
				return
			}

			protocolPolicyAttr := defaultBehaviorBlock.GetAttribute("viewer_protocol_policy")
			if protocolPolicyAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", resourceBlock.FullName()).
					WithBlock(defaultBehaviorBlock)
				return
			}
			if protocolPolicyAttr.Equals("allow-all") {
				set.AddResult().
					WithDescription("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", resourceBlock.FullName()).
					WithAttribute(protocolPolicyAttr)
				return
			}

			orderedBehaviorBlocks := resourceBlock.GetBlocks("ordered_cache_behavior")
			for _, orderedBehaviorBlock := range orderedBehaviorBlocks {
				orderedProtocolPolicyAttr := orderedBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if orderedProtocolPolicyAttr.IsNil() {
					set.AddResult().
						WithDescription("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", resourceBlock.FullName())
				} else if orderedProtocolPolicyAttr.Equals("allow-all") {
					set.AddResult().
						WithDescription("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", resourceBlock.FullName()).
						WithAttribute(orderedProtocolPolicyAttr)
				}
			}

		},
	})
}
