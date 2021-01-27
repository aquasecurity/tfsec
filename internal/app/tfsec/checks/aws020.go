package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedCloudFrontCommunications scanner.RuleCode = "AWS020"
const AWSUnencryptedCloudFrontCommunicationsDescription scanner.RuleSummary = "CloudFront distribution allows unencrypted (HTTP) communications."
const AWSUnencryptedCloudFrontCommunicationsExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const AWSUnencryptedCloudFrontCommunicationsBadExample = `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {
	    viewer_protocol_policy = "allow-all"
	  }
}
`
const AWSUnencryptedCloudFrontCommunicationsGoodExample = `
resource "aws_cloudfront_distribution" "s3_distribution" {
	default_cache_behavior {
	    viewer_protocol_policy = "redirect-to-https"
	  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedCloudFrontCommunications,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedCloudFrontCommunicationsDescription,
			Explanation: AWSUnencryptedCloudFrontCommunicationsExplanation,
			BadExample:  AWSUnencryptedCloudFrontCommunicationsBadExample,
			GoodExample: AWSUnencryptedCloudFrontCommunicationsGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			var results []scanner.Result

			defaultBehaviorBlock := block.GetBlock("default_cache_behavior")
			if defaultBehaviorBlock == nil {
				results = append(results,
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing default_cache_behavior block).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				)
			} else {
				protocolPolicy := defaultBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if protocolPolicy == nil {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					)
				} else if protocolPolicy.Type() == cty.String && protocolPolicy.Value().AsString() == "allow-all" {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", block.FullName()),
							protocolPolicy.Range(),
							protocolPolicy,
							scanner.SeverityError,
						),
					)
				}
			}

			orderedBehaviorBlocks := block.GetBlocks("ordered_cache_behavior")
			for _, orderedBehaviorBlock := range orderedBehaviorBlocks {
				orderedProtocolPolicy := orderedBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if orderedProtocolPolicy == nil {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					)
				} else if orderedProtocolPolicy != nil && orderedProtocolPolicy.Type() == cty.String && orderedProtocolPolicy.Value().AsString() == "allow-all" {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", block.FullName()),
							orderedProtocolPolicy.Range(),
							orderedProtocolPolicy,
							scanner.SeverityError,
						),
					)
				}
			}

			return results

		},
	})
}
