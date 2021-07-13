package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSUnencryptedSQSQueue = "AWS015"
const AWSUnencryptedSQSQueueDescription = "Unencrypted SQS queue."
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedSQSQueue,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sqs_queue"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted SQS queue.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)

			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted SQS queue.", resourceBlock.FullName())).
						WithRange(kmsKeyIDAttr.Range()).
						WithAttributeAnnotation(kmsKeyIDAttr),
				)
			}

		},
	})
}
