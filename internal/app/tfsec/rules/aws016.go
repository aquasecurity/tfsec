package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		CheckFunc: func(block *block.Block, ctx *hclcontext.Context) []result.Result {

			kmsKeyIDAttr := block.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.FullName()),
						kmsKeyIDAttr.Range(),
						kmsKeyIDAttr,
						severity.Error,
					),
				}
			}

			if kmsKeyIDAttr.ReferencesDataBlock() {
				ref := kmsKeyIDAttr.ReferenceAsString()
				dataReferenceParts := strings.Split(ref, ".")
				if len(dataReferenceParts) < 3 {
					return nil
				}
				blockType := dataReferenceParts[0]
				blockName := dataReferenceParts[1]
				kmsKeyDatas := ctx.GetDatasByType(blockType)
				for _, kmsData := range kmsKeyDatas {
					if kmsData.NameLabel() == blockName {
						keyIdAttr := kmsData.GetAttribute("key_id")
						if keyIdAttr != nil && keyIdAttr.Equals("alias/aws/sns") {
							set.Add(
								result.New().WithDescription(
									fmt.Sprintf("Resource '%s' explicitly uses the default CMK", block.FullName()),
									kmsKeyIDAttr.Range(),
									kmsKeyIDAttr,
									severity.Warning,
								),
							}
						}
					}

				}
			}

			return nil
		},
	})
}
