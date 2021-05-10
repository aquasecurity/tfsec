package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedSQSQueue scanner.RuleCode = "AWS015"
const AWSUnencryptedSQSQueueDescription scanner.RuleSummary = "Unencrypted SQS queue."
const AWSUnencryptedSQSQueueImpact = "The SQS queue messages could be read if compromised"
const AWSUnencryptedSQSQueueResolution = "Turn on SQS Queue encryption"
const AWSUnencryptedSQSQueueExplanation = `
Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.
`
const AWSUnencryptedSQSQueueBadExample = `
resource "aws_sqs_queue" "bad_example" {
	# no key specified
}
`
const AWSUnencryptedSQSQueueGoodExample = `
resource "aws_sqs_queue" "good_example" {
	kms_master_key_id = "/blah"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedSQSQueue,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedSQSQueueDescription,
			Impact:      AWSUnencryptedSQSQueueImpact,
			Resolution:  AWSUnencryptedSQSQueueResolution,
			Explanation: AWSUnencryptedSQSQueueExplanation,
			BadExample:  AWSUnencryptedSQSQueueBadExample,
			GoodExample: AWSUnencryptedSQSQueueGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse",
				"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sqs_queue"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			kmsKeyIDAttr := block.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted SQS queue.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted SQS queue.", block.FullName()),
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
