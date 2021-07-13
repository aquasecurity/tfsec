package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

const AWSUnencryptedCloudFrontCommunications = "AWS020"
const AWSUnencryptedCloudFrontCommunicationsDescription = "CloudFront distribution allows unencrypted (HTTP) communications."
const AWSUnencryptedCloudFrontCommunicationsImpact = "CloudFront is available through an unencrypted connection"
const AWSUnencryptedCloudFrontCommunicationsResolution = "Only allow HTTPS for CloudFront distribution communication"
const AWSUnencryptedCloudFrontCommunicationsExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const AWSUnencryptedCloudFrontCommunicationsBadExample = `
resource "aws_cloudfront_distribution" "bad_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "allow-all"
	  }
}
`
const AWSUnencryptedCloudFrontCommunicationsGoodExample = `
resource "aws_cloudfront_distribution" "good_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "redirect-to-https"
	  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedCloudFrontCommunications,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedCloudFrontCommunicationsDescription,
			Impact:      AWSUnencryptedCloudFrontCommunicationsImpact,
			Resolution:  AWSUnencryptedCloudFrontCommunicationsResolution,
			Explanation: AWSUnencryptedCloudFrontCommunicationsExplanation,
			BadExample:  AWSUnencryptedCloudFrontCommunicationsBadExample,
			GoodExample: AWSUnencryptedCloudFrontCommunicationsGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			defaultBehaviorBlock := resourceBlock.GetBlock("default_cache_behavior")
			if defaultBehaviorBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing default_cache_behavior block).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else {
				protocolPolicyAttr := defaultBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if protocolPolicyAttr == nil {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				} else if protocolPolicyAttr.Type() == cty.String && protocolPolicyAttr.Value().AsString() == "allow-all" {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", resourceBlock.FullName())).
							WithRange(protocolPolicyAttr.Range()).
							WithAttributeAnnotation(protocolPolicyAttr),
					)
				}
			}

			orderedBehaviorBlocks := resourceBlock.GetBlocks("ordered_cache_behavior")
			for _, orderedBehaviorBlock := range orderedBehaviorBlocks {
				orderedProtocolPolicyAttr := orderedBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if orderedProtocolPolicyAttr == nil {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				} else if orderedProtocolPolicyAttr.Type() == cty.String && orderedProtocolPolicyAttr.Value().AsString() == "allow-all" {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", resourceBlock.FullName())).
							WithRange(orderedProtocolPolicyAttr.Range()).
							WithAttributeAnnotation(orderedProtocolPolicyAttr),
					)
				}
			}

		},
	})
}
