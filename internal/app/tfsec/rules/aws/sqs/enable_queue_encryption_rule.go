package sqs

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
		LegacyID:  "AWS015",
		Service:   "sqs",
		ShortCode: "enable-queue-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted SQS queue.",
			Impact:     "The SQS queue messages could be read if compromised",
			Resolution: "Turn on SQS Queue encryption",
			Explanation: `
Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.
`,
			BadExample: []string{`
resource "aws_sqs_queue" "bad_example" {
	# no key specified
}
`},
			GoodExample: []string{`
resource "aws_sqs_queue" "good_example" {
	kms_master_key_id = "/blah"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse",
				"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sqs_queue"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted SQS queue.", resourceBlock.FullName())

			} else if kmsKeyIDAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted SQS queue.", resourceBlock.FullName()).
					WithAttribute(kmsKeyIDAttr)
			}

		},
	})
}
