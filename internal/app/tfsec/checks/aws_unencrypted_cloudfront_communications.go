package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedCloudFrontCommunications See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedCloudFrontCommunications scanner.RuleID = "AWS020"
const AWSUnencryptedCloudFrontCommunicationsDescription scanner.RuleDescription = "CloudFront distribution allows unencrypted (HTTP) communications."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedCloudFrontCommunications,
		Description:    AWSUnencryptedCloudFrontCommunicationsDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			var results []scanner.Result

			defaultBehaviorBlock := block.GetBlock("default_cache_behavior")
			if defaultBehaviorBlock == nil {
				results = append(results,
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing default_cache_behavior block).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				)
			} else if defaultBehaviorBlock != nil {
				protocolPolicy := defaultBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if protocolPolicy == nil {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", block.Name()),
							block.Range(),
							scanner.SeverityError,
						),
					)
				} else if protocolPolicy.Type() == cty.String && protocolPolicy.Value().AsString() == "allow-all" {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", block.Name()),
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
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", block.Name()),
							block.Range(),
							scanner.SeverityError,
						),
					)
				} else if orderedProtocolPolicy != nil && orderedProtocolPolicy.Type() == cty.String && orderedProtocolPolicy.Value().AsString() == "allow-all" {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a CloudFront distribution that allows unencrypted communications.", block.Name()),
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
