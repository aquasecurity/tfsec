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

const AWSUnencryptedSNSTopic = "AWS016"
const AWSUnencryptedSNSTopicDescription = "Unencrypted SNS topic."
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedSNSTopic,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedSNSTopicDescription,
			Impact:      AWSUnencryptedSNSTopicImpact,
			Resolution:  AWSUnencryptedSNSTopicResolution,
			Explanation: AWSUnencryptedSNSTopicExplanation,
			BadExample:  AWSUnencryptedSNSTopicBadExample,
			GoodExample: AWSUnencryptedSNSTopicGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse",
				"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sns_topic"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", resourceBlock.FullName())).
						WithRange(kmsKeyIDAttr.Range()).
						WithAttributeAnnotation(kmsKeyIDAttr),
				)
				return
			}

			if kmsKeyIDAttr.IsDataBlockReference() {

				kmsData, err := ctx.GetReferencedBlock(kmsKeyIDAttr)
				if err != nil {
					return
				}

				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr != nil && keyIdAttr.Equals("alias/aws/sns") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' explicitly uses the default CMK", resourceBlock.FullName())).
							WithRange(kmsKeyIDAttr.Range()).
							WithAttributeAnnotation(kmsKeyIDAttr),
					)
				}

			}

		},
	})
}
