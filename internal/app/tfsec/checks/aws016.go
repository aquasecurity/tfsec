package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedSNSTopic scanner.RuleCode = "AWS016"
const AWSUnencryptedSNSTopicDescription scanner.RuleSummary = "Unencrypted SNS topic."
const AWSUnencryptedSNSTopicImpact = "The SNS topic messages could be read if compromised"
const AWSUnencryptedSNSTopicResolution = "Turn on SNS Topic encryption"
const AWSUnencryptedSNSTopicExplanation = `
Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.
`
const AWSUnencryptedSNSTopicBadExample = `
resource "aws_sns_topic" "bad_example" {
	# no key id specified
}
`
const AWSUnencryptedSNSTopicGoodExample = `
resource "aws_sns_topic" "good_example" {
	kms_master_key_id = "/blah"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedSNSTopic,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedSNSTopicDescription,
			Impact:      AWSUnencryptedSNSTopicImpact,
			Resolution:  AWSUnencryptedSNSTopicResolution,
			Explanation: AWSUnencryptedSNSTopicExplanation,
			BadExample:  AWSUnencryptedSNSTopicBadExample,
			GoodExample: AWSUnencryptedSNSTopicGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			kmsKeyIDAttr := block.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.FullName()),
						kmsKeyIDAttr.Range(),
						kmsKeyIDAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
